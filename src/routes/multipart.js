import { v4 as uuidv4 } from 'uuid';
import jwt from "jsonwebtoken";
import SftpClient from 'ssh2-sftp-client';
import { GB, getBearerToken, IAM_URL, isValidUrlSegment, MB, privateKey, getPubKey } from "../Utils.js";
import { Client } from "ssh2";
import { pipeline } from "stream/promises";

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
            return res.code(403).send({ message: "Invalid Permission" });
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
                        return res.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, req.iamData.tokenId, "urn:slabs:iam:fs:bytelake:create-multipart"]);
                }

            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }

        const folderId = req.iamData.extras?.folderId;

        if (folderId && folderId !== folder) {
            return res.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }

        const nameAuth = req.iamData.extras?.name;

        if (nameAuth && nameAuth !== name) {
            return res.code(403).send({ message: "Invalid Permission (name constraint)" });
        }
    }else{
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return res.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canPut = roles.some((p) =>
            p.fsId === "urn:slabs:iam:fs:bytelake:create-multipart" && p.targetURN === lakeId
        );

        if (!canPut) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const folderConstraint = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:create-multipart" && p.targetURN === lakeId)?.extras?.folderId;

        if (folderConstraint && folderConstraint !== folder) {
            return res.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }

        const nameConstraint = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:create-multipart" && p.targetURN === lakeId)?.extras?.name;

        if (nameConstraint && nameConstraint !== name) {
            return res.code(403).send({ message: "Invalid Permission (name constraint)" });
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
                        return res.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:create-multipart"]);
                }
                
            }catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }
    }

    let virtualDir = "";

    if(folder){
        const [parentRows] = await req.server.db.query(
            "SELECT path FROM objects WHERE id = ? AND lakeId = ? AND isFolder = 1",
            [folder, lakeId]
        );

        if (!parentRows || parentRows.length === 0) {
            return reply.code(404).send({ error: "Parent folder not found" });
        }

        virtualDir = parentRows[0].path;
    }

    const virtualPath = `${virtualDir ? virtualDir + "/" : ""}${name}`;

    const [fileAlreadyExists] = await req.server.db.query(
        "SELECT id FROM objects WHERE lakeId = ? AND path = ?",
        [lakeId, virtualPath]
    );

    if (fileAlreadyExists.length > 0) {
        return reply.code(400).send({ error: "File with the same name already exists in the target location" });
    }

    let multipartExistsQuery = "SELECT id FROM multipart WHERE lakeId = ? AND name = ? AND folder " + (folder ? "= ?" : "IS NULL");
    let multipartExistsParams = [lakeId, name, ...(folder ? [folder] : [])];
    const multipartExists = await req.server.db.query(multipartExistsQuery, multipartExistsParams).then(res => res[0].length > 0);

    if(multipartExists){
        return res.status(400).send({ error: "A multipart upload with the same name already exists in the target location" });
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

export async function UploadPart(req, res, SFTP_CONFIG) {
    const { multipartId, partNumber } = req.query;

    if (!multipartId || !partNumber) {
        return res.status(400).send({ error: "Missing required fields" });
    }

    const file = await req.file();
    if (!file) {
        return res.code(400).send({ error: "No file uploaded" });
    }
    
    const multipartInfo = await req.server.db.query("SELECT totalParts, lakeId FROM multipart WHERE id = ?", [multipartId]).then(res => res[0][0]);

    if (!multipartInfo) {
        return res.status(404).send({ error: "Multipart upload not found" });
    }

    if (partNumber <= 0 || partNumber > multipartInfo.totalParts) {
        return res.status(400).send({ error: "Invalid part number" });
    }

    const token = getBearerToken(req);

    if (!token) {
        return res.code(401).send({ error: "Missing or invalid Authorization header" });
    }

    let decoded;
    const pubKey = await getPubKey();

    try {
        decoded = jwt.verify(token, pubKey, { algorithms: ["RS256"] });
    } catch {
        return res.code(403).send({ message: "Invalid Token" });
    }

    if(decoded.fsId !== "urn:slabs:iam:fs:bytelake:upload-part" || decoded.resourceName !== multipartInfo.lakeId){
        return res.code(403).send({ message: "Invalid Permission" });
    }

    const maxUsages = decoded.extras?.maxUsages;

    if (typeof maxUsages === "number" && maxUsages > 0) {
        try {
            const [trlInfo] = await req.server.db.query("SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?", [decoded.jti, "urn:slabs:iam:fs:bytelake:upload-part"]);

            if(trlInfo.length === 0){
                await req.server.db.query("INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)", [decoded.jti, 1, new Date(), new Date((decoded.exp*1000)+10000), "urn:slabs:iam:fs:bytelake:upload-part"]);
            }else{
                const currentUsages = trlInfo[0].usages;

                if(currentUsages >= decoded.extras.maxUsages){
                    return res.code(401).send({ message: 'Maximum usage limit reached' });
                }

                await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, decoded.jti, "urn:slabs:iam:fs:bytelake:upload-part"]);
            }

        } catch (err) {
            console.error("Error occurred while fetching TRL info:", err);
            return res.code(500).send({ error: "Internal server error" });
        }
    }

    const multipartRestriction = decoded.extras?.multipartId;

    if (multipartRestriction && multipartRestriction !== multipartId) {
        return res.code(403).send({ message: "Invalid Permission (multipart constraint)" });
    }

    const validateExisting = await req.server.db.query("SELECT id FROM multipartObjects WHERE multipartId = ? AND partNumber = ?", [multipartId, partNumber]).then(res => res[0][0]);

    const sftp = new SftpClient();

    const partId = uuidv4();

    try {
        await sftp.connect(SFTP_CONFIG);

        await sftp.mkdir("/usr/bytelake-parts/" + multipartId.replaceAll(":","-"), true).catch(() => { return res.status(500).send({ error: "Failed to create multipart directory on SFTP" }); });
        const remoteWriteStream = sftp.createWriteStream("/usr/bytelake-parts/" + multipartId.replaceAll(":","-") + "/" + partId, { flags: "w" });

        await pipeline(file.file, remoteWriteStream);

        const objectId = `urn:slabs:bytelake:${multipartId}:${partId}`;
        
        if(validateExisting){
            await req.server.db.query(
                "UPDATE multipartObjects SET createdAt = ? WHERE multipartId = ? AND partNumber = ?",
                [new Date(), multipartId, partNumber]
            );
        }else{
            await req.server.db.query(
                "INSERT INTO multipartObjects (id, partNumber, createdAt, multipartId) VALUES (?, ?, ?, ?)",
                [objectId, partNumber, new Date(), multipartId]
            );
        }

        return res.code(200).send({
            uploaded: true,
            updated: !!validateExisting,
            partNumber,
            partId: objectId
        });
    } catch (err) {
        console.log(err);
        return res.code(500).send({ error: "SFTP upload failed" });
    } finally {
        try { await sftp.end(); } catch {}
    }
}

export async function GetMissingParts(req, res) {
    const { multipartId } = req.query;

    if (!multipartId) {
        return res.status(400).send({ error: "Missing required fields" });
    }

    const multipartInfo = await req.server.db.query("SELECT lakeId, totalParts FROM multipart WHERE id = ?", [multipartId]).then(res => res[0][0]);

    if(req.iamData.singleTarget){
        if(req.iamData.fsId !== "urn:slabs:iam:fs:bytelake:create-multipart" || req.iamData.resourceName !== multipartInfo.lakeId){
            return res.code(403).send({ message: "Invalid Permission" });
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
                        return res.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, req.iamData.tokenId, "urn:slabs:iam:fs:bytelake:create-multipart"]);
                }

            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }
    }else{
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return res.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canPut = roles.some((p) =>
            p.fsId === "urn:slabs:iam:fs:bytelake:create-multipart" && p.targetURN === multipartInfo.lakeId
        );

        if (!canPut) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const maxUsages = roles.reduce((max, role) => {
            if (role.fsId === "urn:slabs:iam:fs:bytelake:create-multipart" && role.targetURN === multipartInfo.lakeId) {
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
                        return res.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:create-multipart"]);
                }
                
            }catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }
    }

    const missingParts = await req.server.db.query("SELECT partNumber FROM multipartObjects WHERE multipartId = ?", [multipartId]).then(res => {
        const totalParts = multipartInfo.totalParts;
        const missing = [];

        const uploaded = new Set(res[0].map(r => r.partNumber))

        for(let i=1; i <= totalParts; i++){
            if(!uploaded.has(i)){
                missing.push(i)
            }
        }

        return missing;
    });

    return res.code(200).send({
        missingParts
    });
}

export async function CompletePartsUpload(req, res) {
    const { multipartId } = req.query;

    if (!multipartId) {
        return res.status(400).send({ error: "Missing required fields" });
    }

    const multipartInfo = await req.server.db.query("SELECT lakeId, totalParts, multipart.name, folder, lakes.path FROM multipart INNER JOIN lakes ON multipart.lakeId = lakes.id WHERE multipart.id = ?", [multipartId]).then(res => res[0][0]);

    if(req.iamData.singleTarget){
        if(req.iamData.fsId !== "urn:slabs:iam:fs:bytelake:create-multipart" || req.iamData.resourceName !== multipartInfo.lakeId){
            return res.code(403).send({ message: "Invalid Permission" });
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
                        return res.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, req.iamData.tokenId, "urn:slabs:iam:fs:bytelake:create-multipart"]);
                }

            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }
    }else{
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return res.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canPut = roles.some((p) =>
            p.fsId === "urn:slabs:iam:fs:bytelake:create-multipart" && p.targetURN === multipartInfo.lakeId
        );

        if (!canPut) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const maxUsages = roles.reduce((max, role) => {
            if (role.fsId === "urn:slabs:iam:fs:bytelake:create-multipart" && role.targetURN === multipartInfo.lakeId) {
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
                        return res.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:create-multipart"]);
                }
                
            }catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }
    }

    const parts = await req.server.db.query("SELECT id FROM multipartObjects WHERE multipartId = ? ORDER BY partNumber ASC", [multipartId]).then(res => res[0]);

    if(parts.length !== multipartInfo.totalParts){
        return res.code(400).send({ error: "Not all parts have been uploaded" });
    }

    let folderPath = "";

    if (multipartInfo.folder) {
        const [folder] = await req.server.db.query(
            "SELECT path FROM objects WHERE id = ?",
            [multipartInfo.folder]
        );

        if (folder.length === 0) {
            return res.code(400).send({ error: "Invalid folder reference" });
        }

        folderPath = folder[0].path;
    }

    const finalPath = "/usr/bytelake/" + multipartInfo.path + "/" + (folderPath ? folderPath + "/" : "") + multipartInfo.name;
    const concatenatedContent = "cat " + parts.map(p => "/usr/bytelake-parts/" + multipartId.replaceAll(":","-") + "/" + p.id.split(":").pop()).join(" ") + " > " + finalPath;

    await new Promise((resolve, reject) => {
        const conn = new Client();
        conn.on("ready", async () => {
            conn.exec(concatenatedContent, (err, stream) => {
                if (err) {
                    conn.end();
                    return reject(err);
                }

                let exitCode = null;

                stream.on("data", () => {});

                stream.on("exit", (code) => {
                    exitCode = code;
                });

                stream.on("close", () => {
                    conn.end();
                    if (exitCode === 0) {
                        resolve();
                    } else {
                        reject(new Error("CAT failed"));
                    }
                });

                stream.stderr.on("data", (data) => {
                    console.error("SSH STDERR:", data.toString());
                });
            })
        }).on("error", e => console.error("Erro SSH:", e.message))
        .connect({
            host: process.env.SFTP_HOST,
            port: Number(process.env.SFTP_PORT),
            username: process.env.SFTP_USER,
            password: process.env.SFTP_PASS
        });
    })

    const fileId = uuidv4();
    const objectId = `urn:slabs:bytelake:${multipartInfo.path}:${fileId}`;
    const virtualPath = (folderPath ? folderPath + "/" : "") + multipartInfo.name;

    await req.server.db.query(
        "INSERT INTO objects (id, name, path, createdAt, lakeId, isFolder, parentId) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [objectId, multipartInfo.name, virtualPath, new Date(), multipartInfo.lakeId, false, multipartInfo.folder || null]
    );

    await req.server.db.query("DELETE FROM multipartObjects WHERE multipartId = ?", [multipartId]);
    await req.server.db.query("DELETE FROM multipart WHERE id = ?", [multipartId]);

    const connDelete = new Client();
    connDelete.on("ready", () => {
        connDelete.exec("rm -rf /usr/bytelake-parts/" + multipartId.replaceAll(":","-"), (err, stream) => {
            if (err) {
                console.error("Erro ao apagar multipart:", err.message);
                connDelete.end();
                return;
            }

            stream.on("close", (code) => {
                if (code !== 0) {
                    connDelete.end();
                    return;
                }
            });
        });
    }).on("error", e => console.error("Erro SSH:", e.message))
    .connect({
        host: process.env.SFTP_HOST,
        port: Number(process.env.SFTP_PORT),
        username: process.env.SFTP_USER,
        password: process.env.SFTP_PASS
    });

    res.code(200).send({
        uploaded: true,
        objectId,
        filePath: virtualPath,
        originalName: multipartInfo.name
    });
}

export async function AbortMultipart(req, res) {
    const { multipartId } = req.query;

    if (!multipartId) {
        return res.status(400).send({ error: "Missing required fields" });
    }

    const multipartInfo = await req.server.db.query("SELECT lakeId FROM multipart WHERE id = ?", [multipartId]).then(res => res[0][0]);

    if(req.iamData.singleTarget){
        if(req.iamData.fsId !== "urn:slabs:iam:fs:bytelake:delete-multipart" || req.iamData.resourceName !== multipartInfo.lakeId){
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const multipartIdIAM = req.iamData.extras?.multipartId;

        if (multipartIdIAM && multipartIdIAM !== multipartId) {
            return res.code(403).send({ message: "Invalid Permission (multipart constraint)" });
        }
    }else{
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return res.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canPut = roles.some((p) =>
            p.fsId === "urn:slabs:iam:fs:bytelake:delete-multipart" && p.targetURN === multipartInfo.lakeId
        );

        if (!canPut) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const multipartIdIAM = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:delete-multipart" && p.targetURN === multipartInfo.lakeId)?.extras?.multipartId;

        if (multipartIdIAM && multipartIdIAM !== multipartId) {
            return res.code(403).send({ message: "Invalid Permission (multipart constraint)" });
        }
    }

    const conn = new Client();
    conn.on("ready", () => {
        conn.exec("rm -rf /usr/bytelake-parts/" + multipartId.replaceAll(":","-"), (err, stream) => {
            if (err) {
                console.error("Erro ao concatenar ficheiro:", err.message);
                conn.end();
                return;
            }

            stream.on("close", (code) => {
                if (code !== 0) {
                    conn.end();
                    return;
                }
            });
        });
    }).on("error", e => console.error("Erro SSH:", e.message))
    .connect({
        host: process.env.SFTP_HOST,
        port: Number(process.env.SFTP_PORT),
        username: process.env.SFTP_USER,
        password: process.env.SFTP_PASS
    });

    await req.server.db.query("DELETE FROM multipartObjects WHERE multipartId = ?", [multipartId]);
    await req.server.db.query("DELETE FROM multipart WHERE id = ?", [multipartId]);

    return res.code(200).send({
        aborted: true
    });
}