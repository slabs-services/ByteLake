import { v4 as uuidv4 } from 'uuid';
import SftpClient from 'ssh2-sftp-client';
import { pipeline } from 'stream/promises';
import jwt from "jsonwebtoken";
import { getBearerToken, getPubKey, isValidUrlSegment } from '../Utils.js';
import path from "path";

export async function PutObject(req, reply, sftpConfig) {
    const { lakeId, parentId } = req.query;

    if (!lakeId) {
        return reply.code(400).send({ error: "No lake ID provided" });
    }

    const file = await req.file();
    if (!file) {
        return reply.code(400).send({ error: "No file uploaded" });
    }

    if (!isValidUrlSegment(file.filename)) {
        return reply.code(400).send({ error: "File name needs to be a valid URL segment" });
    }

    const token = getBearerToken(req);

    if (!token) {
        return reply.code(401).send({ error: "Missing or invalid Authorization header" });
    }

    let decoded;
    const pubKey = await getPubKey();

    try {
        decoded = jwt.verify(token, pubKey, { algorithms: ["RS256"] });
    } catch {
        return reply.code(403).send({ message: "Invalid Token" });
    }

    if(decoded.singleTarget){
        if(decoded.fsId !== "urn:slabs:iam:fs:bytelake:put" || decoded.resourceName !== lakeId){
            return reply.code(403).send({ message: "Invalid Permission" });
        }

        const maxUsages = decoded.extras?.maxUsages;

        if (typeof maxUsages === "number" && maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query("SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?", [decoded.jti, "urn:slabs:iam:fs:bytelake:put"]);

                if(trlInfo.length === 0){
                    await req.server.db.query("INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)", [decoded.jti, 1, new Date(), new Date((decoded.exp*1000)+10000), "urn:slabs:iam:fs:bytelake:put"]);
                }else{
                    const currentUsages = trlInfo[0].usages;

                    if(currentUsages >= decoded.extras.maxUsages){
                        return reply.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, decoded.jti, "urn:slabs:iam:fs:bytelake:put"]);
                }

            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return reply.code(500).send({ error: "Internal server error" });
            }
        }

        const folderId = decoded.extras?.folderId;

        if (folderId && folderId !== parentId) {
            return reply.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }
    }else{
        const roles = decoded.roles;

        if (!Array.isArray(roles)) {
            return reply.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canPut = roles.some((p) =>
            p.fsId === "urn:slabs:iam:fs:bytelake:put" && p.targetURN === lakeId
        );

        if (!canPut) {
            return reply.code(403).send({ message: "Invalid Permission" });
        }

        const folderConstraint = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:put" && p.targetURN === lakeId)?.extras?.folderId;

        if (folderConstraint && folderConstraint !== parentId) {
            return reply.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }

        const maxUsages = roles.reduce((max, role) => {
            if (role.fsId === "urn:slabs:iam:fs:bytelake:put" && role.targetURN === lakeId) {
                const roleMaxUsages = role.extras?.maxUsages;
                if (typeof roleMaxUsages === "number" && roleMaxUsages > 0) {
                    return Math.max(max, roleMaxUsages);
                }
            }
            return max;
        }, 0);

        if (maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query("SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?", [decoded.jti, "urn:slabs:iam:fs:bytelake:put"]);

                if(trlInfo.length === 0){
                    await req.server.db.query("INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)", [decoded.jti, 1, new Date(), new Date((decoded.exp*1000)+10000), "urn:slabs:iam:fs:bytelake:put"]);
                }else{
                    const currentUsages = trlInfo[0].usages;

                    if(currentUsages >= maxUsages){
                        return reply.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, decoded.jti, "urn:slabs:iam:fs:bytelake:put"]);
                }
                
            }catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return reply.code(500).send({ error: "Internal server error" });
            }
        }
    }

    const [lakeRows] = await req.server.db.query(
        "SELECT path FROM lakes WHERE id = ?",
        [lakeId]
    );

    if (!lakeRows || lakeRows.length === 0) {
        return reply.code(404).send({ error: "Lake not found" });
    }

    let virtualDir = "";

    if(parentId){
        const [parentRows] = await req.server.db.query(
            "SELECT path FROM objects WHERE id = ? AND lakeId = ? AND isFolder = 1",
            [parentId, lakeId]
        );

        if (!parentRows || parentRows.length === 0) {
            return reply.code(404).send({ error: "Parent folder not found" });
        }

        virtualDir = parentRows[0].path;
    }

    const lakePath = lakeRows[0].path;

    const virtualPath = `${virtualDir ? virtualDir + "/" : ""}${file.filename}`;

    const [fileAlreadyExists] = await req.server.db.query(
        "SELECT id FROM objects WHERE lakeId = ? AND path = ?",
        [lakeId, virtualPath]
    );

    if (fileAlreadyExists.length > 0) {
        return reply.code(400).send({ error: "File with the same name already exists in the target location" });
    }

    const [multipartAlreadyExists] = await req.server.db.query(
        "SELECT id FROM multipart WHERE lakeId = ? AND name = ? AND folder " + (parentId ? "= ?" : "IS NULL"),
        [lakeId, file.filename, ...(parentId ? [parentId] : [])]
    );

    if (multipartAlreadyExists.length > 0) {
        return reply.code(400).send({ error: "A multipart upload with the same name already exists in the target location" });
    }

    const remotePath = `/usr/bytelake/${lakePath}/${virtualPath}`;

    const sftp = new SftpClient();

    try {
        await sftp.connect(sftpConfig);

        const remoteWriteStream = sftp.createWriteStream(remotePath, { flags: "w" });

        await pipeline(file.file, remoteWriteStream);

        const fileId = uuidv4();
        const objectId = `urn:slabs:bytelake:${lakePath}:${fileId}`;

        await req.server.db.query(
            "INSERT INTO objects (id, name, path, createdAt, lakeId, isFolder, parentId) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [objectId, file.filename, virtualPath, new Date(), lakeId, false, parentId || null]
        );

        return reply.code(200).send({
            uploaded: true,
            objectId,
            filePath: virtualPath,
            originalName: file.filename,
        });
    } catch (err) {
        return reply.code(500).send({ error: "SFTP upload failed" });
    } finally {
        try { await sftp.end(); } catch {}
    }
}

export async function ObjectMetadata(req, res) {
  const { objectId } = req.params;
  if (!objectId){
    return res.code(400).send({ error: 'Object ID is required' });
  }

  const [objects] = await req.server.db.query('SELECT objects.path AS objectPath, lakes.path AS lakePath FROM objects INNER JOIN lakes ON objects.lakeId = lakes.id WHERE objects.id = ?', [objectId]);
  if (objects.length === 0){
    return res.code(404).send({ error: 'Object not found' });
  }

  return {
    path: objects[0].objectPath,
    lakePath: objects[0].lakePath
  }
}

export async function DeleteObject(req, res, SFTP_CONFIG) {
    const { targetURN, objectId } = req.body;

    if (!targetURN || !objectId) {
        return res.code(400).send({ message: "Invalid Request Body" });
    }

    if (req.iamData.singleTarget) {
        if (req.iamData.fsId !== "urn:slabs:iam:fs:bytelake:delete" || req.iamData.resourceName !== targetURN) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const maxUsages = req.iamData.extras?.maxUsages;

        if (typeof maxUsages === "number" && maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query(
                    "SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?",
                    [req.iamData.jti, "urn:slabs:iam:fs:bytelake:delete"]
                );

                if (trlInfo.length === 0) {
                    await req.server.db.query(
                        "INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)",
                        [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp * 1000) + 10000), "urn:slabs:iam:fs:bytelake:delete"]
                    );
                } else {
                    const currentUsages = trlInfo[0].usages;

                    if (currentUsages >= maxUsages) {
                        return res.code(401).send({ message: "Maximum usage limit reached" });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:delete"]
                    );
                }
            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }

        const objectConstraint = req.iamData.extras?.objectId;
        if (objectConstraint && objectConstraint !== objectId) {
            return res.code(403).send({ message: "Invalid Permission (object constraint)" });
        }
    } else {
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return res.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canDelete = roles.some((p) => p.fsId === "urn:slabs:iam:fs:bytelake:delete" && p.targetURN === targetURN);

        if (!canDelete) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const objectConstraint = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:delete" && p.targetURN === targetURN)?.extras?.objectId;

        if (objectConstraint && objectConstraint !== objectId) {
            return res.code(403).send({ message: "Invalid Permission (object constraint)" });
        }

        const maxUsages = roles.reduce((max, role) => {
            if (role.fsId === "urn:slabs:iam:fs:bytelake:delete" && role.targetURN === targetURN) {
                const roleMaxUsages = role.extras?.maxUsages;
                if (typeof roleMaxUsages === "number" && roleMaxUsages > 0) {
                    return Math.max(max, roleMaxUsages);
                }
            }
            return max;
        }, 0);

        if (maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query(
                    "SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?",
                    [req.iamData.jti, "urn:slabs:iam:fs:bytelake:delete"]
                );

                if (trlInfo.length === 0) {
                    await req.server.db.query(
                        "INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)",
                        [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp * 1000) + 10000), "urn:slabs:iam:fs:bytelake:delete"]
                    );
                } else {
                    const currentUsages = trlInfo[0].usages;

                    if (currentUsages >= maxUsages) {
                        return res.code(401).send({ message: "Maximum usage limit reached" });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:delete"]
                    );
                }
            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }
    }

    const [lakeRows] = await req.server.db.query(
        "SELECT path FROM lakes WHERE id = ?",
        [targetURN]
    );

    if (!lakeRows || lakeRows.length === 0) {
        return res.code(404).send({ error: "Lake not found" });
    }

    const [objectRows] = await req.server.db.query(
        "SELECT id, name, path, isFolder, lakeId FROM objects WHERE id = ? AND lakeId = ?",
        [objectId, targetURN]
    );

    if (!objectRows || objectRows.length === 0) {
        return res.code(404).send({ error: "Object not found" });
    }

    const object = objectRows[0];

    if (object.isFolder) {
        return res.code(400).send({ error: "The provided object is a folder, not a file" });
    }

    const remotePath = `/usr/bytelake/${lakeRows[0].path}/${object.path}`;

    const sftp = new SftpClient();

    try {
        await sftp.connect(SFTP_CONFIG);

        const exists = await sftp.exists(remotePath);
        if (!exists) {
            return res.code(404).send({ error: "Object not found in storage" });
        }

        await sftp.delete(remotePath);
    } catch (err) {
        console.error("Error occurred while deleting object on SFTP:", err);
        return res.code(500).send({ error: "Failed to delete object from storage" });
    } finally {
        try {
            await sftp.end();
        } catch {}
    }

    try {
        await req.server.db.query(
            "DELETE FROM objects WHERE id = ? AND lakeId = ?",
            [objectId, targetURN]
        );
    } catch (err) {
        console.error("Error occurred while deleting object from DB:", err);
        return res.code(500).send({
            error: "Object removed from storage, but database cleanup failed"
        });
    }

    return res.code(200).send({
        deleted: true,
        objectId
    });
}

export async function RenameObject(req, res, SFTP_CONFIG) {
    const { targetURN, objectId, newObjectName } = req.body;

    if (!targetURN || !objectId || !newObjectName || !newObjectName.trim()) {
        return res.code(400).send({ message: "Invalid Request Body" });
    }

    if (!isValidUrlSegment(newObjectName.trim())) {
        return res.code(400).send({ message: "Object name must be a valid URL segment" });
    }

    if (req.iamData.singleTarget) {
        if (req.iamData.fsId !== "urn:slabs:iam:fs:bytelake:rename" || req.iamData.resourceName !== targetURN) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const maxUsages = req.iamData.extras?.maxUsages;

        if (typeof maxUsages === "number" && maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query(
                    "SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?",
                    [req.iamData.jti, "urn:slabs:iam:fs:bytelake:rename"]
                );

                if (trlInfo.length === 0) {
                    await req.server.db.query(
                        "INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)",
                        [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp * 1000) + 10000), "urn:slabs:iam:fs:bytelake:rename"]
                    );
                } else {
                    const currentUsages = trlInfo[0].usages;

                    if (currentUsages >= maxUsages) {
                        return res.code(401).send({ message: "Maximum usage limit reached" });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:rename"]
                    );
                }
            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }

        const objectConstraint = req.iamData.extras?.objectId;
        if (objectConstraint && objectConstraint !== objectId) {
            return res.code(403).send({ message: "Invalid Permission (object constraint)" });
        }
    } else {
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return res.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canRename = roles.some((p) => p.fsId === "urn:slabs:iam:fs:bytelake:rename" && p.targetURN === targetURN);

        if (!canRename) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const objectConstraint = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:rename" && p.targetURN === targetURN)?.extras?.objectId;

        if (objectConstraint && objectConstraint !== objectId) {
            return res.code(403).send({ message: "Invalid Permission (object constraint)" });
        }

        const maxUsages = roles.reduce((max, role) => {
            if(role.fsId === "urn:slabs:iam:fs:bytelake:rename" && role.targetURN === targetURN) {
                const roleMaxUsages = role.extras?.maxUsages;
                if (typeof roleMaxUsages === "number" && roleMaxUsages > 0) {
                    return Math.max(max, roleMaxUsages);
                }
            }
            return max;
        }, 0);

        if (maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query(
                    "SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?",
                    [req.iamData.jti, "urn:slabs:iam:fs:bytelake:rename"]
                );

                if (trlInfo.length === 0) {
                    await req.server.db.query(
                        "INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)",
                        [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp * 1000) + 10000), "urn:slabs:iam:fs:bytelake:rename"]
                    );
                } else {
                    const currentUsages = trlInfo[0].usages;

                    if (currentUsages >= maxUsages) {
                        return res.code(401).send({ message: "Maximum usage limit reached" });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:rename"]
                    );
                }
            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }
    }

    const [lakeRows] = await req.server.db.query(
        "SELECT path FROM lakes WHERE id = ?",
        [targetURN]
    );

    if (!lakeRows || lakeRows.length === 0) {
        return res.code(404).send({ error: "Lake not found" });
    }

    const [objectRows] = await req.server.db.query(
        "SELECT id, name, path, parentId, isFolder FROM objects WHERE id = ? AND lakeId = ?",
        [objectId, targetURN]
    );

    if (!objectRows || objectRows.length === 0) {
        return res.code(404).send({ error: "Object not found" });
    }

    const object = objectRows[0];

    if (object.isFolder) {
        return res.code(400).send({ error: "The provided object is a folder, not a file" });
    }

    const trimmedNewName = newObjectName.trim();

    if (object.name === trimmedNewName) {
        return res.code(200).send({
            renamed: true,
            objectId,
            oldPath: object.path,
            newPath: object.path
        });
    }

    const oldPath = object.path;

    let newPath;
    if (object.parentId == null) {
        newPath = trimmedNewName;
    } else {
        const dirPath = path.posix.dirname(oldPath);
        newPath = dirPath === "." ? trimmedNewName : `${dirPath}/${trimmedNewName}`;
    }

    const oldRemotePath = `/usr/bytelake/${lakeRows[0].path}/${oldPath}`;
    const newRemotePath = `/usr/bytelake/${lakeRows[0].path}/${newPath}`;

    const [duplicateRows] = await req.server.db.query("SELECT id FROM objects WHERE lakeId = ? AND path = ? AND id <> ?", [targetURN, newPath, objectId]);

    if (duplicateRows.length > 0) {
        return res.code(400).send({ error: "An object with the same name already exists in the target location" });
    }

    const sftp = new SftpClient();

    try {
        await sftp.connect(SFTP_CONFIG);

        const oldExists = await sftp.exists(oldRemotePath);
        if (!oldExists) {
            return res.code(404).send({ error: "Object not found in storage" });
        }

        const newExists = await sftp.exists(newRemotePath);
        if (newExists) {
            return res.code(400).send({ error: "An object with the target name already exists in storage" });
        }

        await sftp.rename(oldRemotePath, newRemotePath);
    } catch (err) {
        console.error("Error occurred while renaming object on SFTP:", err);
        return res.code(500).send({ error: "Failed to rename object in storage" });
    } finally {
        try {
            await sftp.end();
        } catch {}
    }

    try {
        await req.server.db.query(
            "UPDATE objects SET name = ?, path = ? WHERE id = ? AND lakeId = ?",
            [trimmedNewName, newPath, objectId, targetURN]
        );
    } catch (err) {
        console.error("Error occurred while updating object in DB:", err);
        return res.code(500).send({
            error: "Object renamed in storage, but database update failed"
        });
    }

    return res.code(200).send({
        renamed: true,
        objectId,
        oldPath,
        newPath
    });
}

export async function MoveObject(req, reply, SFTP_CONFIG) {
    const { targetURN, objectId, newParentId } = req.body;

    if (!targetURN || !objectId) {
        return reply.code(400).send({ message: "Invalid Request Body" });
    }

    const normalizedNewParentId = newParentId || null;

    if (req.iamData.singleTarget) {
        if (req.iamData.fsId !== "urn:slabs:iam:fs:bytelake:move" || req.iamData.resourceName !== targetURN) {
            return reply.code(403).send({ message: "Invalid Permission" });
        }

        const maxUsages = req.iamData.extras?.maxUsages;

        if (typeof maxUsages === "number" && maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query(
                    "SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?",
                    [req.iamData.jti, "urn:slabs:iam:fs:bytelake:move"]
                );

                if (trlInfo.length === 0) {
                    await req.server.db.query(
                        "INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)",
                        [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp * 1000) + 10000), "urn:slabs:iam:fs:bytelake:move"]
                    );
                } else {
                    const currentUsages = trlInfo[0].usages;

                    if (currentUsages >= maxUsages) {
                        return reply.code(401).send({ message: "Maximum usage limit reached" });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:move"]
                    );
                }
            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return reply.code(500).send({ error: "Internal server error" });
            }
        }

        const objectConstraint = req.iamData.extras?.objectId;
        if (objectConstraint && objectConstraint !== objectId) {
            return reply.code(403).send({ message: "Invalid Permission (object constraint)" });
        }
    } else {
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return reply.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canMove = roles.some((p) => p.fsId === "urn:slabs:iam:fs:bytelake:move" && p.targetURN === targetURN);

        if (!canMove) {
            return reply.code(403).send({ message: "Invalid Permission" });
        }

        const objectConstraint = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:move" && p.targetURN === targetURN)?.extras?.objectId;

        if (objectConstraint && objectConstraint !== objectId) {
            return reply.code(403).send({ message: "Invalid Permission (object constraint)" });
        }

        const maxUsages = roles.reduce((max, role) => {
            if(role.fsId === "urn:slabs:iam:fs:bytelake:move" && role.targetURN === targetURN) {
                const roleMaxUsages = role.extras?.maxUsages;
                if (typeof roleMaxUsages === "number" && roleMaxUsages > 0) {
                    return Math.max(max, roleMaxUsages);
                }
            }
            return max;
        }, 0);

        if (maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query(
                    "SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?",
                    [req.iamData.jti, "urn:slabs:iam:fs:bytelake:move"]
                );

                if (trlInfo.length === 0) {
                    await req.server.db.query("INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)", [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp * 1000) + 10000), "urn:slabs:iam:fs:bytelake:move"]);
                } else {
                    const currentUsages = trlInfo[0].usages;

                    if (currentUsages >= maxUsages) {
                        return reply.code(401).send({ message: "Maximum usage limit reached" });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:move"]
                    );
                }
            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return reply.code(500).send({ error: "Internal server error" });
            }
        }
    }

    const [lakeRows] = await req.server.db.query(
        "SELECT path FROM lakes WHERE id = ?",
        [targetURN]
    );

    if (!lakeRows || lakeRows.length === 0) {
        return reply.code(404).send({ error: "Lake not found" });
    }

    const lakePath = lakeRows[0].path;

    const [objectRows] = await req.server.db.query(
        "SELECT id, name, path, parentId, isFolder FROM objects WHERE id = ? AND lakeId = ?",
        [objectId, targetURN]
    );

    if (!objectRows || objectRows.length === 0) {
        return reply.code(404).send({ error: "Object not found" });
    }

    const object = objectRows[0];

    if (object.isFolder) {
        return reply.code(400).send({ error: "The provided object is a folder, not a file" });
    }

    if (object.parentId === normalizedNewParentId) {
        return reply.code(200).send({
            moved: true,
            objectId,
            oldPath: object.path,
            newPath: object.path
        });
    }

    let newParentPath = "";
    if (normalizedNewParentId) {
        const [parentRows] = await req.server.db.query(
            "SELECT id, path, isFolder FROM objects WHERE id = ? AND lakeId = ?",
            [normalizedNewParentId, targetURN]
        );

        if (!parentRows || parentRows.length === 0) {
            return reply.code(404).send({ error: "Destination parent folder not found" });
        }

        if (!parentRows[0].isFolder) {
            return reply.code(400).send({ error: "Destination parent is not a folder" });
        }

        newParentPath = parentRows[0].path;
    }

    const oldPath = object.path;
    const newPath = `${newParentPath ? newParentPath + "/" : ""}${object.name}`;

    const [duplicateRows] = await req.server.db.query(
        "SELECT id FROM objects WHERE lakeId = ? AND path = ? AND id <> ? LIMIT 1",
        [targetURN, newPath, objectId]
    );

    if (duplicateRows.length > 0) {
        return reply.code(400).send({
            error: "An object with the same name already exists in the target location"
        });
    }

    const oldRemotePath = `/usr/bytelake/${lakePath}/${oldPath}`;
    const newRemotePath = `/usr/bytelake/${lakePath}/${newPath}`;

    const sftp = new SftpClient();

    try {
        await sftp.connect(SFTP_CONFIG);

        const oldExists = await sftp.exists(oldRemotePath);
        if (!oldExists) {
            return reply.code(404).send({ error: "Object not found in storage" });
        }

        const newExists = await sftp.exists(newRemotePath);
        if (newExists) {
            return reply.code(400).send({
                error: "An object with the same name already exists in storage"
            });
        }

        await sftp.rename(oldRemotePath, newRemotePath);
    } catch (err) {
        console.error("Error occurred while moving object on SFTP:", err);
        return reply.code(500).send({ error: "Failed to move object in storage" });
    } finally {
        try {
            await sftp.end();
        } catch {}
    }

    try {
        await req.server.db.query(
            "UPDATE objects SET parentId = ?, path = ? WHERE id = ? AND lakeId = ?",
            [normalizedNewParentId, newPath, objectId, targetURN]
        );
    } catch (err) {
        console.error("Error occurred while updating object in DB:", err);
        return reply.code(500).send({
            error: "Object moved in storage, but database update failed"
        });
    }

    return reply.code(200).send({
        moved: true,
        objectId,
        oldParentId: object.parentId,
        newParentId: normalizedNewParentId,
        oldPath,
        newPath
    });
}