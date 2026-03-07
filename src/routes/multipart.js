import { v4 as uuidv4 } from 'uuid';
import jwt from "jsonwebtoken";
import { BYTELAKE_URL, GB, IAM_URL, isValidUrlSegment, MB, privateKey } from "../Utils.js";

export async function CreateMultipart(req, res) {
    const { name, lakeId, fileSize, partSize, folder, maxTime } = req.body;

    if (!name || !lakeId || !fileSize || !partSize || !maxTime) {
        return res.status(400).send({ error: "Missing required fields" });
    }

    if (!isValidUrlSegment(name)){
        return res.status(400).send({ error: "Name needs to be a valid URL segment" });
    }

    if (partSize <= 0 || fileSize <= 0){
        return res.status(400).send({ error: "File size and part size must be greater than 0" });
    }

    if (partSize < 5 * MB || partSize > 10 * MB) {
        return res.status(400).send({
            error: "Part size must be between 5MB and 10MB"
        });
    }

    if(fileSize > 256 * GB){
        return res.status(400).send({ error: "File size must be less than or equal to 256GB" });
    }

    if(maxTime <= 0 || maxTime > 7 * 24 * 3600){
        return res.status(400).send({ error: "Max time must be between 1 second and 7 days (in seconds)" });
    }

    if(partSize > fileSize){
        return res.status(400).send({ error: "Part size cannot be greater than file size" });
    }

    const totalParts = Math.ceil(fileSize / partSize);

    if(req.iamData.singleTarget){
        if(req.iamData.fsId !== "urn:slabs:iam:fs:bytelake:create-multipart" || req.iamData.resourceName !== lakeId){
            return reply.code(403).send({ message: "Invalid Permission" });
        }

        const maxUsages = req.iamData.extras?.maxUsages;

        if (typeof maxUsages === "number" && maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query("SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?", [req.iamData.tokenId, "urn:slabs:iam:fs:bytelake:create-multipart"]);

                if(trlInfo.length === 0){
                    await req.server.db.query("INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)", [req.iamData.tokenId, 1, new Date(), new Date((req.iamData.exp*1000)+10000), "urn:slabs:iam:fs:bytelake:create-multipart"]);
                }else{
                    const currentUsages = trlInfo[0].usages;

                    if(currentUsages >= req.iamData.extras.maxUsages){
                        return reply.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, req.iamData.tokenId, "urn:slabs:iam:fs:bytelake:create-multipart"]);
                }

            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return reply.code(500).send({ error: "Internal server error" });
            }
        }

        const folderId = req.iamData.extras?.folderId;

        if (folderId && folderId !== folder) {
            return reply.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }

        const nameAuth = req.iamData.extras?.name;

        if (nameAuth && nameAuth !== name) {
            return reply.code(403).send({ message: "Invalid Permission (name constraint)" });
        }
    }else{
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return reply.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canPut = roles.some((p) =>
            p.fsId === "urn:slabs:iam:fs:bytelake:create-multipart" && p.targetURN === lakeId
        );

        if (!canPut) {
            return reply.code(403).send({ message: "Invalid Permission" });
        }

        const folderConstraint = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:create-multipart" && p.targetURN === lakeId)?.extras?.folderId;

        if (folderConstraint && folderConstraint !== folder) {
            return reply.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }

        const nameConstraint = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:create-multipart" && p.targetURN === lakeId)?.extras?.name;

        if (nameConstraint && nameConstraint !== name) {
            return reply.code(403).send({ message: "Invalid Permission (name constraint)" });
        }

        const maxUsages = roles.reduce((max, role) => {
            if (role.fsId === "urn:slabs:iam:fs:bytelake:create-multipart" && role.targetURN === lakeId) {
                const roleMaxUsages = role.extras?.maxUsages;
                if (typeof roleMaxUsages === "number" && roleMaxUsages > 0) {
                    return Math.max(max, roleMaxUsages);
                }
            }
            return max;
        }, 0);

        if (maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query("SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?", [req.iamData.jti, "urn:slabs:iam:fs:bytelake:create-multipart"]);

                if(trlInfo.length === 0){
                    await req.server.db.query("INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)", [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp*1000)+10000), "urn:slabs:iam:fs:bytelake:create-multipart"]);
                }else{
                    const currentUsages = trlInfo[0].usages;

                    if(currentUsages >= maxUsages){
                        return reply.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:create-multipart"]);
                }
                
            }catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return reply.code(500).send({ error: "Internal server error" });
            }
        }
    }

    const multipartId = "urn:slabs:bytelake:multipart:" + uuidv4();

    await req.server.db.query("INSERT INTO multipart (id, name, lakeId, totalParts, folder, createdAt) VALUES (?, ?, ?, ?, ?, ?)", [multipartId, name, lakeId, totalParts, folder || null, new Date()]);

    const authService = jwt.sign({
        userId: req.iamData.userId
    }, privateKey, {
        algorithm: "RS256",
        header: {
            kid: "urn:slabs:iam:serviceaccount:bytelake-cp"
        },
        expiresIn: "10s"
    });

    const token = await fetch(IAM_URL + "/timedTokensServices", {
        method: "POST",
        body: JSON.stringify({
            fsId: "urn:slabs:iam:fs:bytelake:upload-part",
            resourceName: lakeId,
            expiresIn: maxTime,
            extras: {
                multipartId,
                maxUsages: Math.ceil(totalParts * 1.05)
            }
        }),
        headers: {
            "Authorization": `Bearer ${authService}`,
            "Content-Type": "application/json"
        }
    }).then(res => res.json()).then(data => data.token).catch(err => {
        console.error("Error occurred while fetching upload token:", err);
        return null;
    });

    if(!token){
        return res.status(500).send({ error: "Failed to generate upload token" });
    }

    return {
        multipartId,
        partsUploadSignedToken: token
    }
}