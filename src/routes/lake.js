import { slugify, updateBindSerial } from "../Utils.js";
import SftpClient from 'ssh2-sftp-client';
import { Client } from "ssh2";
import { v4 as uuidv4 } from 'uuid';

export async function CreateLake(req, res, sftpConfig){
    const { lakeName, isPrivate } = req.body;

    if (!lakeName){
        return res.status(400).send({ error: 'Lake name is required' });
    }

    if(req.iamData.singleTarget){
        if(req.iamData.fsId !== "urn:slabs:iam:fs:bytelake:create"){
            res.status(400).send({ error: "You dont have permission to create a bytelake." });
            return;
        }

        const maxUsages = req.iamData.extras?.maxUsages;

        if (typeof maxUsages === "number" && maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query("SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?", [req.iamData.jti, "urn:slabs:iam:fs:bytelake:create"]);

                if(trlInfo.length === 0){
                    await req.server.db.query("INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)", [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp*1000)+10000), "urn:slabs:iam:fs:bytelake:create"]);
                }else{
                    const currentUsages = trlInfo[0].usages;

                    if(currentUsages >= req.iamData.extras.maxUsages){
                        return reply.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:create"]);
                }

            } catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return reply.code(500).send({ error: "Internal server error" });
            }
        }
    }else{
        const roles = req.iamData.roles;

        if (!Array.isArray(roles)) {
            return reply.code(403).send({ message: "Invalid Token (missing roles)" });
        }

        const canPut = roles.some((p) =>
            p.fsId === "urn:slabs:iam:fs:bytelake:create" && p.targetURN === lakeId
        );

        if (!canPut) {
            return reply.code(403).send({ message: "Invalid Permission" });
        }

        const maxUsages = roles.reduce((max, role) => {
            if (role.fsId === "urn:slabs:iam:fs:bytelake:create") {
                const roleMaxUsages = role.extras?.maxUsages;
                if (typeof roleMaxUsages === "number" && roleMaxUsages > 0) {
                    return Math.max(max, roleMaxUsages);
                }
            }
            return max;
        }, 0);

        if (maxUsages > 0) {
            try {
                const [trlInfo] = await req.server.db.query("SELECT usages FROM tokensRevoked WHERE tokenId = ? AND fsId = ?", [req.iamData.jti, "urn:slabs:iam:fs:bytelake:create"]);

                if(trlInfo.length === 0){
                    await req.server.db.query("INSERT INTO tokensRevoked (tokenId, usages, createdAt, expiresAt, fsId) VALUES (?, ?, ?, ?, ?)", [req.iamData.jti, 1, new Date(), new Date((req.iamData.exp*1000)+10000), "urn:slabs:iam:fs:bytelake:create"]);
                }else{
                    const currentUsages = trlInfo[0].usages;

                    if(currentUsages >= maxUsages){
                        return reply.code(401).send({ message: 'Maximum usage limit reached' });
                    }

                    await req.server.db.query("UPDATE tokensRevoked SET usages = ? WHERE tokenId = ? AND fsId = ?", [currentUsages + 1, req.iamData.jti, "urn:slabs:iam:fs:bytelake:create"]);
                }
                
            }catch (err) {
                console.error("Error occurred while fetching TRL info:", err);
                return reply.code(500).send({ error: "Internal server error" });
            }
        }
    }

    const slug = slugify(lakeName);

    const sftpFolder = new SftpClient();
    sftpFolder.connect(sftpConfig)
    .then(() => sftpFolder.mkdir(`/usr/bytelake/${slug}`, true))
    .then(() => req.server.db.query('INSERT INTO lakes (id, name, path, isPrivate, ownerId) VALUES (?, ?, ?, ?, ?)', ["urn:slabs:bytelake:" + slug, lakeName, slug, isPrivate, req.iamData.userId]))
    .then(() => req.server.db.query('INSERT INTO hosts (id, host, lakeId) VALUES (?, ?, ?)', [uuidv4(), slug + ".lake.tryspacelabs.pt", "urn:slabs:bytelake:" + slug]))
    .then(() => res.send({ created: true, lakeName: "urn:slabs:bytelake:" + slug }))
    .catch(err => {
      console.error('Lake creation failed', err);
      res.status(500).send({ error: 'Lake creation failed' });
    })
    .finally(() => sftpFolder.end());

    const conn = new Client();
    conn.on("ready", () => {
        conn.exec("cat /etc/bind/zones/db.tryspacelabs.pt", (err, stream) => {
            if (err) {
                console.error("Erro a ler ficheiro:", err.message);
                conn.end();
                return;
            }

            let data = "";

            stream.on("data", chunk => {
                data += chunk.toString();
            });

            stream.on("close", (code) => {
                if (code !== 0) {
                    conn.end();
                    return;
                }

                let serialUpdated = updateBindSerial(data);

                const newLine = `${slug}.lake\tIN\tA\t192.168.1.12\n`;
                serialUpdated += newLine;

                const sftp = new SftpClient();
                sftp.connect({
                    host: process.env.DNS_HOST,
                    port: Number(process.env.DNS_PORT),
                    username: process.env.DNS_USER,
                    password: process.env.DNS_PASS
                })
                .then(() => sftp.put(Buffer.from(serialUpdated, "utf8"), "/etc/bind/zones/db.tryspacelabs.pt"))
                .then(() => {
                    conn.exec("sudo /usr/sbin/rndc reload tryspacelabs.pt", (err, stream) => {
                        if (err) {
                            console.error("Erro ao dar reload:", err.message);
                            conn.end();
                            return;
                        }

                        stream.on("close", () => {
                            conn.end();
                        });
                    });
                })
                .catch(err => {
                  console.error('Lake creation failed', err);
                  res.status(500).send({ error: 'Lake creation failed' });
                })
                .finally(() => sftp.end());
            });
        });
    }).on("error", e => console.error("Erro SSH:", e.message))
    .connect({
        host: process.env.DNS_HOST,
        port: Number(process.env.DNS_PORT),
        username: process.env.DNS_USER,
        password: process.env.DNS_PASS
    });

    return {
        created: true,
        lakeName: "urn:slabs:bytelake:" + slug
    }
}