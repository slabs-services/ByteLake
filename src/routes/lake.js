import { slugify, updateBindSerial } from "../Utils.js";
import SftpClient from 'ssh2-sftp-client';
import { Client } from "ssh2";

export async function CreateLake(req, res, sftpConfig){
    const { lakeName, isPrivate } = req.body;

    if (!lakeName){
        return res.status(400).send({ error: 'Lake name is required' });
    }

    const slug = slugify(lakeName);

    const sftpFolder = new SftpClient();
    sftpFolder.connect(sftpConfig)
    .then(() => sftpFolder.mkdir(`/usr/bytelake/${slug}`, true))
    .then(() => req.server.db.query('INSERT INTO lakes (id, name, path, isPrivate) VALUES (?, ?, ?, ?)', ["urn:slabs:bytelake:" + slug, lakeName, slug, isPrivate]))
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