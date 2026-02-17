import { v4 as uuidv4 } from 'uuid';
import SftpClient from 'ssh2-sftp-client';
import { pipeline } from 'stream/promises';
import path from "path";
import jwt from "jsonwebtoken";
import { getBearerToken, getPubKey } from '../Utils.js';

export async function PutObject(req, reply, sftpConfig) {
    const { lakeId } = req.params;

    if (!lakeId) {
        return reply.code(400).send({ error: "No lake ID provided" });
    }

    const file = await req.file();
    if (!file) {
        return reply.code(400).send({ error: "No file uploaded" });
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
    }

    const [lakeRows] = await req.server.db.query(
        "SELECT path FROM lakes WHERE id = ?",
        [lakeId]
    );

    if (!lakeRows || lakeRows.length === 0) {
        return reply.code(404).send({ error: "Lake not found" });
    }

    const lakePath = lakeRows[0].path;

    const fileId = uuidv4();
    const ext = path.extname(file.filename ?? "");
    const fileName = `${fileId}${ext}`;

    const remoteDir = `/usr/bytelake/${lakePath}`;
    const remotePath = `${remoteDir}/${fileName}`;

    const sftp = new SftpClient();

    try {
        await sftp.connect(sftpConfig);

        await sftp.mkdir(remoteDir, true);

        const remoteWriteStream = sftp.createWriteStream(remotePath, { flags: "w" });

        await pipeline(file.file, remoteWriteStream);

        const objectId = `urn:slabs:bytelake:${lakePath}:${fileId}`;

        await req.server.db.query(
            "INSERT INTO objects (id, name, path, createdAt, lakeId, isFolder, parentId) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [objectId, file.filename, fileName, new Date(), lakeId, false, null]
        );

        return reply.code(200).send({
            uploaded: true,
            objectId,
            fileName,
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
    return res.status(400).send({ error: 'Object ID is required' });
  }

  const [objects] = await req.server.db.query('SELECT objects.path AS objectPath, lakes.path AS lakePath FROM objects INNER JOIN lakes ON objects.lakeId = lakes.id WHERE objects.id = ?', [objectId]);
  if (objects.length === 0){
    return res.status(404).send({ error: 'Object not found' });
  }

  return {
    path: objects[0].objectPath,
    lakePath: objects[0].lakePath
  }
}