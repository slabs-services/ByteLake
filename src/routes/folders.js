import { getFolderSubtree, isValidUrlSegment } from "../Utils.js";
import { v4 as uuidv4 } from 'uuid';
import SftpClient from 'ssh2-sftp-client';

export async function CreateFolder(req, res, SFTP_CONFIG) {
    const { targetURN, parentId, folderName } = req.body;

    if(!targetURN || !folderName || !folderName.trim()){
        return res.code(400).send({ message: "Invalid Request Body" });
    }

    if(!isValidUrlSegment(folderName)){
        return res.code(400).send({ message: "Folder name needs to be a valid URL segment" });
    }

    if(req.iamData.singleTarget){
        if(req.iamData.fsId !== "urn:slabs:iam:fs:bytelake:create-folder" || req.iamData.resourceName !== targetURN){
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const maxUsages = req.iamData.extras?.maxUsages;

        if (typeof maxUsages === "number" && maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query("SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?", [req.iamData.jti, "urn:slabs:iam:fs:bytelake:create-folder"]);

                if(trlInfo.length === 0){
                    await req.server.db.query("INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)", [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp*1000)+10000), "urn:slabs:iam:fs:bytelake:create-folder"]);
                }else{
                    const currentUsages = trlInfo[0].usages;

                    if(currentUsages >= req.iamData.extras.maxUsages){
                        return res.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:create-folder"]
                    );
                }

            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }

        const folderId = req.iamData.extras?.parentId;

        if (folderId && folderId !== parentId) {
            return res.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }
    }else{
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return res.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canPut = roles.some((p) =>
            p.fsId === "urn:slabs:iam:fs:bytelake:create-folder" && p.targetURN === targetURN
        );

        if (!canPut) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const folderConstraint = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:create-folder" && p.targetURN === targetURN)?.extras?.parentId;

        if (folderConstraint && folderConstraint !== parentId) {
            return res.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }

        const maxUsages = roles.reduce((max, role) => {
            if (role.fsId === "urn:slabs:iam:fs:bytelake:create-folder" && role.targetURN === targetURN) {
                const roleMaxUsages = role.extras?.maxUsages;
                if (typeof roleMaxUsages === "number" && roleMaxUsages > 0) {
                    return Math.max(max, roleMaxUsages);
                }
            }
            return max;
        }, 0);

        if (maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query("SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?", [req.iamData.jti, "urn:slabs:iam:fs:bytelake:create-folder"]);

                if(trlInfo.length === 0){
                    await req.server.db.query("INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)", [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp*1000)+10000), "urn:slabs:iam:fs:bytelake:create-folder"]);
                }else{
                    const currentUsages = trlInfo[0].usages;

                    if(currentUsages >= maxUsages){
                        return res.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:create-folder"]);
                }
                
            }catch (err) {
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

    let query;
    let params;

    if (parentId == null) {
        query = "SELECT id FROM objects WHERE lakeId = ? AND name = ? AND parentId IS NULL AND isFolder = 1";
        params = [targetURN, folderName];
    } else {
        query = "SELECT id FROM objects WHERE lakeId = ? AND name = ? AND parentId = ? AND isFolder = 1";
        params = [targetURN, folderName, parentId];
    }

    const [folderPath] = await req.server.db.query(query, params);

    if(folderPath.length > 0){
        return res.code(400).send({ error: "Folder with the same name already exists in the target location" });
    }

    const localId = uuidv4();
    let parentPath = null;

    if (parentId) {
        const [parentRows] = await req.server.db.query(
            "SELECT path FROM objects WHERE id = ? AND lakeId = ? AND isFolder = 1",
            [parentId, targetURN]
        );

        if (!parentRows || parentRows.length === 0) {
            return res.code(404).send({ error: "Parent folder not found" });
        }

        parentPath = parentRows[0].path;
    }

    const smallRemoteDir = `${parentPath ? parentPath + "/" : ""}${folderName.trim()}`;
    const remoteDir = `/usr/bytelake/${lakeRows[0].path}/${smallRemoteDir}`;
    const folderId = "urn:slabs:bytelake:" + lakeRows[0].path + ":" + localId;

    await req.server.db.query(
        "INSERT INTO objects (id, name, path, createdAt, lakeId, isFolder, parentId) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [folderId, folderName.trim(), smallRemoteDir, new Date(), targetURN, true, parentId || null]
    );

    const sftp = new SftpClient();

    try {
        await sftp.connect(SFTP_CONFIG);
        await sftp.mkdir(remoteDir, true);
    }catch(err){
        console.error("Error occurred while creating folder on SFTP:", err);
        return res.code(500).send({ error: "Internal server error" });
    }finally{
        sftp.end();
    }

    return res.code(200).send({ created: true, folderId });
}

export async function DeleteFolder(req, res, SFTP_CONFIG) {
    const { targetURN, folderId } = req.body;

    if (!targetURN || !folderId) {
        return res.code(400).send({ message: "Invalid Request Body" });
    }

    if (req.iamData.singleTarget) {
        if (req.iamData.fsId !== "urn:slabs:iam:fs:bytelake:delete-folder" || req.iamData.resourceName !== targetURN) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const maxUsages = req.iamData.extras?.maxUsages;

        if (typeof maxUsages === "number" && maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query(
                    "SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?",
                    [req.iamData.jti, "urn:slabs:iam:fs:bytelake:delete-folder"]
                );

                if (trlInfo.length === 0) {
                    await req.server.db.query(
                        "INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)",
                        [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp * 1000) + 10000), "urn:slabs:iam:fs:bytelake:delete-folder"]
                    );
                }else{
                    const currentUsages = trlInfo[0].usages;

                    if (currentUsages >= maxUsages) {
                        return res.code(401).send({ message: "Maximum usage limit reached" });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:delete-folder"]
                    );
                }
            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }

        const folderConstraint = req.iamData.extras?.folderId;
        if (folderConstraint && folderConstraint !== folderId) {
            return res.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }
    } else {
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return res.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canDelete = roles.some((p) => p.fsId === "urn:slabs:iam:fs:bytelake:delete-folder" && p.targetURN === targetURN);

        if (!canDelete) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const folderConstraint = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:delete-folder" && p.targetURN === targetURN)?.extras?.folderId;

        if (folderConstraint && folderConstraint !== folderId) {
            return res.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }

        const maxUsages = roles.reduce((max, role) => {
            if(role.fsId === "urn:slabs:iam:fs:bytelake:delete-folder" && role.targetURN === targetURN) {
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
                    [req.iamData.jti, "urn:slabs:iam:fs:bytelake:delete-folder"]
                );

                if (trlInfo.length === 0) {
                    await req.server.db.query(
                        "INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)",
                        [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp * 1000) + 10000), "urn:slabs:iam:fs:bytelake:delete-folder"]
                    );
                } else {
                    const currentUsages = trlInfo[0].usages;

                    if (currentUsages >= maxUsages) {
                        return res.code(401).send({ message: "Maximum usage limit reached" });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:delete-folder"]
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

    const [folderRows] = await req.server.db.query(
        "SELECT id, name, path, isFolder, parentId FROM objects WHERE id = ? AND lakeId = ?",
        [folderId, targetURN]
    );

    if (!folderRows || folderRows.length === 0) {
        return res.code(404).send({ error: "Folder not found" });
    }

    if (!folderRows[0].isFolder) {
        return res.code(400).send({ error: "The provided object is not a folder" });
    }

    const folder = folderRows[0];
    const remoteDir = `/usr/bytelake/${lakeRows[0].path}/${folder.path}`;

    let subtree;
    try {
        subtree = await getFolderSubtree(req.server.db, folderId, targetURN);
    } catch (err) {
        console.error("Error while loading subtree:", err);
        return res.code(500).send({ error: "Internal server error" });
    }

    if (!subtree || subtree.length === 0) {
        return res.code(404).send({ error: "Folder subtree not found" });
    }

    const idsToDelete = subtree.map((row) => row.id);

    const sftp = new SftpClient();

    try {
        await sftp.connect(SFTP_CONFIG);

        const exists = await sftp.exists(remoteDir);
        if (exists) {
            await sftp.rmdir(remoteDir, true);
        }
    } catch (err) {
        console.error("Error occurred while deleting folder on SFTP:", err);
        return res.code(500).send({ error: "Failed to delete folder from storage" });
    } finally {
        try {
            await sftp.end();
        } catch {}
    }

    const conn = await req.server.db.getConnection();

    try {
        await conn.beginTransaction();

        const placeholders = idsToDelete.map(() => "?").join(", ");
        await conn.query(
            `DELETE FROM objects WHERE id IN (${placeholders})`,
            idsToDelete
        );

        await conn.commit();
    } catch (err) {
        await conn.rollback();
        console.error("Error occurred while deleting folder subtree from DB:", err);
        return res.code(500).send({
            error: "Folder removed from storage, but database cleanup failed"
        });
    } finally {
        conn.release();
    }

    return res.code(200).send({
        deleted: true,
        folderId,
        deletedObjects: idsToDelete.length
    });
}

export async function RenameFolder(req, res, SFTP_CONFIG) {
    const { targetURN, folderId, newFolderName } = req.body;

    if (!targetURN || !folderId || !newFolderName || !newFolderName.trim()) {
        return res.code(400).send({ message: "Invalid Request Body" });
    }

    if (!isValidUrlSegment(newFolderName.trim())) {
        return res.code(400).send({ message: "Folder name must be a valid URL segment" });
    }

    if (req.iamData.singleTarget) {
        if (req.iamData.fsId !== "urn:slabs:iam:fs:bytelake:rename-folder" || req.iamData.resourceName !== targetURN) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const maxUsages = req.iamData.extras?.maxUsages;

        if (typeof maxUsages === "number" && maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query(
                    "SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?",
                    [req.iamData.jti, "urn:slabs:iam:fs:bytelake:rename-folder"]
                );

                if (trlInfo.length === 0) {
                    await req.server.db.query(
                        "INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)",
                        [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp * 1000) + 10000), "urn:slabs:iam:fs:bytelake:rename-folder"]
                    );
                } else {
                    const currentUsages = trlInfo[0].usages;

                    if (currentUsages >= maxUsages) {
                        return res.code(401).send({ message: "Maximum usage limit reached" });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:rename-folder"]
                    );
                }
            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return res.code(500).send({ error: "Internal server error" });
            }
        }

        const folderConstraint = req.iamData.extras?.folderId;
        if (folderConstraint && folderConstraint !== folderId) {
            return res.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }
    } else {
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return res.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canRename = roles.some((p) => p.fsId === "urn:slabs:iam:fs:bytelake:rename-folder" && p.targetURN === targetURN);

        if (!canRename) {
            return res.code(403).send({ message: "Invalid Permission" });
        }

        const folderConstraint = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:rename-folder" && p.targetURN === targetURN)?.extras?.folderId;

        if (folderConstraint && folderConstraint !== folderId) {
            return res.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }

        const maxUsages = roles.reduce((max, role) => {
            if(role.fsId === "urn:slabs:iam:fs:bytelake:rename-folder" && role.targetURN === targetURN) {
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
                    [req.iamData.jti, "urn:slabs:iam:fs:bytelake:rename-folder"]
                );

                if (trlInfo.length === 0) {
                    await req.server.db.query(
                        "INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)",
                        [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp * 1000) + 10000), "urn:slabs:iam:fs:bytelake:rename-folder"]
                    );
                } else {
                    const currentUsages = trlInfo[0].usages;

                    if (currentUsages >= maxUsages) {
                        return res.code(401).send({ message: "Maximum usage limit reached" });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:rename-folder"]
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

    const [folderRows] = await req.server.db.query(
        "SELECT id, name, path, parentId, isFolder FROM objects WHERE id = ? AND lakeId = ?",
        [folderId, targetURN]
    );

    if (!folderRows || folderRows.length === 0) {
        return res.code(404).send({ error: "Folder not found" });
    }

    const folder = folderRows[0];

    if (!folder.isFolder) {
        return res.code(400).send({ error: "The provided object is not a folder" });
    }

    const trimmedNewName = newFolderName.trim();

    if (folder.name === trimmedNewName) {
        return res.code(200).send({
            renamed: true,
            folderId,
            oldPath: folder.path,
            newPath: folder.path
        });
    }

    let duplicateQuery;
    let duplicateParams;

    if (folder.parentId == null) {
        duplicateQuery = `
            SELECT id
            FROM objects
            WHERE lakeId = ?
              AND parentId IS NULL
              AND isFolder = 1
              AND name = ?
              AND id <> ?
            LIMIT 1
        `;
        duplicateParams = [targetURN, trimmedNewName, folderId];
    } else {
        duplicateQuery = `
            SELECT id
            FROM objects
            WHERE lakeId = ?
              AND parentId = ?
              AND isFolder = 1
              AND name = ?
              AND id <> ?
            LIMIT 1
        `;
        duplicateParams = [targetURN, folder.parentId, trimmedNewName, folderId];
    }

    const [duplicateRows] = await req.server.db.query(duplicateQuery, duplicateParams);

    if (duplicateRows.length > 0) {
        return res.code(400).send({ error: "Folder with the same name already exists in the target location" });
    }

    const oldPath = folder.path;

    let newPath;
    if (folder.parentId == null) {
        newPath = trimmedNewName;
    } else {
        const [parentRows] = await req.server.db.query(
            "SELECT path FROM objects WHERE id = ? AND lakeId = ? AND isFolder = 1",
            [folder.parentId, targetURN]
        );

        if (!parentRows || parentRows.length === 0) {
            return res.code(400).send({ error: "Parent folder not found" });
        }

        newPath = `${parentRows[0].path}/${trimmedNewName}`;
    }

    const oldRemotePath = `/usr/bytelake/${lakeRows[0].path}/${oldPath}`;
    const newRemotePath = `/usr/bytelake/${lakeRows[0].path}/${newPath}`;

    const sftp = new SftpClient();

    try {
        await sftp.connect(SFTP_CONFIG);

        const exists = await sftp.exists(oldRemotePath);
        if (!exists) {
            return res.code(404).send({ error: "Folder not found in storage" });
        }

        const targetExists = await sftp.exists(newRemotePath);
        if (targetExists) {
            return res.code(400).send({ error: "A folder with the target name already exists in storage" });
        }

        await sftp.rename(oldRemotePath, newRemotePath);
    } catch (err) {
        console.error("Error occurred while renaming folder on SFTP:", err);
        return res.code(500).send({ error: "Failed to rename folder in storage" });
    } finally {
        try {
            await sftp.end();
        } catch {}
    }

    const conn = await req.server.db.getConnection();

    try {
        await conn.beginTransaction();

        await conn.query(
            "UPDATE objects SET name = ?, path = ? WHERE id = ? AND lakeId = ?",
            [trimmedNewName, newPath, folderId, targetURN]
        );

        await conn.query(
            `
            UPDATE objects
            SET path = CONCAT(?, SUBSTRING(path, ?))
            WHERE lakeId = ?
              AND path LIKE ?
              AND id <> ?
            `,
            [newPath, oldPath.length + 1, targetURN, `${oldPath}/%`, folderId]
        );

        await conn.commit();
    } catch (err) {
        await conn.rollback();
        console.error("Error occurred while updating folder paths in DB:", err);
        return res.code(500).send({
            error: "Folder renamed in storage, but database update failed"
        });
    } finally {
        conn.release();
    }

    return res.code(200).send({
        renamed: true,
        folderId,
        oldPath,
        newPath
    });
}

export async function MoveFolder(req, reply, SFTP_CONFIG) {
    const { targetURN, folderId, newParentId } = req.body;

    if (!targetURN || !folderId) {
        return reply.code(400).send({ message: "Invalid Request Body" });
    }

    const normalizedNewParentId = newParentId || null;

    if (req.iamData.singleTarget) {
        if(req.iamData.fsId !== "urn:slabs:iam:fs:bytelake:move-folder" || req.iamData.resourceName !== targetURN) {
            return reply.code(403).send({ message: "Invalid Permission" });
        }

        const maxUsages = req.iamData.extras?.maxUsages;

        if (typeof maxUsages === "number" && maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query(
                    "SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?",
                    [req.iamData.jti, "urn:slabs:iam:fs:bytelake:move-folder"]
                );

                if (trlInfo.length === 0) {
                    await req.server.db.query(
                        "INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)",
                        [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp * 1000) + 10000), "urn:slabs:iam:fs:bytelake:move-folder"]
                    );
                } else {
                    const currentUsages = trlInfo[0].usages;

                    if (currentUsages >= maxUsages) {
                        return reply.code(401).send({ message: "Maximum usage limit reached" });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:move-folder"]
                    );
                }
            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return reply.code(500).send({ error: "Internal server error" });
            }
        }

        const folderConstraint = req.iamData.extras?.folderId;
        if (folderConstraint && folderConstraint !== folderId) {
            return reply.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }
    } else {
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return reply.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canMove = roles.some((p) => p.fsId === "urn:slabs:iam:fs:bytelake:move-folder" && p.targetURN === targetURN);

        if (!canMove) {
            return reply.code(403).send({ message: "Invalid Permission" });
        }

        const folderConstraint = roles.find((p) => p.fsId === "urn:slabs:iam:fs:bytelake:move-folder" && p.targetURN === targetURN)?.extras?.folderId;

        if (folderConstraint && folderConstraint !== folderId) {
            return reply.code(403).send({ message: "Invalid Permission (folder constraint)" });
        }

        const maxUsages = roles.reduce((max, role) => {
            if(role.fsId === "urn:slabs:iam:fs:bytelake:move-folder" && role.targetURN === targetURN) {
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
                    [req.iamData.jti, "urn:slabs:iam:fs:bytelake:move-folder"]
                );

                if (trlInfo.length === 0) {
                    await req.server.db.query(
                        "INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)",
                        [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp * 1000) + 10000), "urn:slabs:iam:fs:bytelake:move-folder"]
                    );
                } else {
                    const currentUsages = trlInfo[0].usages;

                    if (currentUsages >= maxUsages) {
                        return reply.code(401).send({ message: "Maximum usage limit reached" });
                    }

                    await req.server.db.query(
                        "UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?",
                        [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:move-folder"]
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

    const [folderRows] = await req.server.db.query(
        "SELECT id, name, path, parentId, isFolder FROM objects WHERE id = ? AND lakeId = ?",
        [folderId, targetURN]
    );

    if (!folderRows || folderRows.length === 0) {
        return reply.code(404).send({ error: "Folder not found" });
    }

    const folder = folderRows[0];

    if (!folder.isFolder) {
        return reply.code(400).send({ error: "The provided object is not a folder" });
    }

    if (folder.parentId === normalizedNewParentId) {
        return reply.code(200).send({
            moved: true,
            folderId,
            oldPath: folder.path,
            newPath: folder.path
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

    const oldPath = folder.path;
    const newPath = `${newParentPath ? newParentPath + "/" : ""}${folder.name}`;

    if (normalizedNewParentId && (newParentPath === oldPath || newParentPath.startsWith(oldPath + "/"))) {
        return reply.code(400).send({
            error: "Cannot move a folder into itself or one of its descendants"
        });
    }

    const [duplicateRows] = await req.server.db.query(
        "SELECT id FROM objects WHERE lakeId = ? AND path = ? AND id <> ? LIMIT 1",
        [targetURN, newPath, folderId]
    );

    if (duplicateRows.length > 0) {
        return reply.code(400).send({
            error: "Folder with the same name already exists in the target location"
        });
    }

    const oldRemotePath = `/usr/bytelake/${lakePath}/${oldPath}`;
    const newRemotePath = `/usr/bytelake/${lakePath}/${newPath}`;

    const sftp = new SftpClient();

    try {
        await sftp.connect(SFTP_CONFIG);

        const oldExists = await sftp.exists(oldRemotePath);
        if (!oldExists) {
            return reply.code(404).send({ error: "Folder not found in storage" });
        }

        const newExists = await sftp.exists(newRemotePath);
        if (newExists) {
            return reply.code(400).send({
                error: "A folder with the same name already exists in storage"
            });
        }

        await sftp.rename(oldRemotePath, newRemotePath);
    } catch (err) {
        console.error("Error occurred while moving folder on SFTP:", err);
        return reply.code(500).send({ error: "Failed to move folder in storage" });
    } finally {
        try {
            await sftp.end();
        } catch {}
    }

    const conn = await req.server.db.getConnection();

    try {
        await conn.beginTransaction();

        await conn.query(
            "UPDATE objects SET parentId = ?, path = ? WHERE id = ? AND lakeId = ?",
            [normalizedNewParentId, newPath, folderId, targetURN]
        );

        await conn.query(
            `
            UPDATE objects
            SET path = CONCAT(?, SUBSTRING(path, ?))
            WHERE lakeId = ?
              AND path LIKE ?
              AND id <> ?
            `,
            [
                newPath,
                oldPath.length + 1,
                targetURN,
                `${oldPath}/%`,
                folderId
            ]
        );

        await conn.commit();
    } catch (err) {
        await conn.rollback();
        console.error("Error occurred while updating folder paths in DB:", err);
        return reply.code(500).send({
            error: "Folder moved in storage, but database update failed"
        });
    } finally {
        conn.release();
    }

    return reply.code(200).send({
        moved: true,
        folderId,
        oldParentId: folder.parentId,
        newParentId: normalizedNewParentId,
        oldPath,
        newPath
    });
}