import { getPubKey } from "../Utils.js";
import jwt from "jsonwebtoken";

export async function CheckOwner(req, reply) {
    if(req.host !== 'storage.bytelake.slabs.pt'){
        return reply.status(404).send({
            "message": "Invalid Route"
        });
    }

    const resourceName = req.query.resourceName;
    const accountRequested = req.query.accountRequested;

    if(!resourceName || !accountRequested){
        return reply.status(400).send({
            "message": "Missing Resource Name or Account Requested"
        });
    }

    const urnFormat = resourceName.split(":");

    if(urnFormat.length === 4){
        const [ownerCheck] = await req.server.db.query("SELECT id FROM lakes WHERE id = ? AND ownerId = ?", [resourceName, accountRequested]);

        if(ownerCheck.length === 0){
            return reply.status(401).send({
                "message": "Resource does not exists or is not the owner."
            });
        }else{
            return reply.status(200).send({
                "message": "Owner OK"
            });
        }
    }else{
        const [ownerCheck] = await req.server.db.query("SELECT objects.id FROM objects INNER JOIN lakes ON objects.lakeId = lakes.id WHERE objects.id = ? AND lakes.ownerId = ?", [resourceName, accountRequested]);

        if(ownerCheck.length === 0){
            return reply.status(401).send({
                "message": "Resource does not exists or is not the owner."
            });
        }else{
            return reply.status(200).send({
                "message": "Owner OK"
            });
        }
    }
}

export async function ValidatePermissions(req, res) {
    if(req.host !== 'storage.bytelake.slabs.pt'){
        return res.status(403).send('Forbidden');
    }
    
    const lakeMetadata = await req.server.db.query('SELECT lakes.isPrivate AS isPrivate, lakes.path as path, lakes.id AS lakeId FROM lakes INNER JOIN hosts ON hosts.lakeId = lakes.id WHERE hosts.host = ?', [req.headers['x-original-host']]);
    if (lakeMetadata[0].length === 0) {
        return res.status(404).send('Lake not found');
    }

    if (!lakeMetadata[0][0].isPrivate) {
        return res.header('X-Lake-Root', lakeMetadata[0][0].path).send('ok');
    }

    const originalUri = req.headers["x-original-uri"];
    const url = new URL(originalUri, "http://dummy");
    const authorization = url.searchParams.get("authorization");

    if (!authorization) {
        return res.status(403).send('Authorization query parameter is required');
    }

    const pubKey = await getPubKey();

    try {
        const decoded = jwt.verify(authorization, pubKey, {
            algorithms: ["RS256"],
        });

        if(decoded.singleTarget){
            if(decoded.fsId !== "urn:slabs:iam:fs:bytelake:read"){
                return res.status(403).send("Forbidden");
            }

            const [object] = await req.server.db.query('SELECT path FROM objects WHERE id = ?', [decoded.resourceName]);

            if(!object){
                return res.status(403).send("Forbidden");
            }

            const allowedPath = object[0].path;

            if(allowedPath !== url.pathname.slice(1)){
                return res.status(403).send("Forbidden");
            }
        }else{
            const roles = decoded.roles;

            const readRoles = roles.filter((role) => {
                return role.fsId === "urn:slabs:iam:fs:bytelake:read";
            });

            if(readRoles.length === 0){
                return res.status(403).send("Forbidden");
            }

            const urnFormat = readRoles[0].targetURN.split(":");

            if(urnFormat.length === 4){
                const exists = readRoles.some(p => {
                    return p.targetURN === lakeMetadata[0][0].lakeId
                });

                if(!exists){
                    return res.status(403).send("Forbidden");
                }
            }else{
                const [object] = await req.server.db.query('SELECT id FROM objects WHERE path = ?', [url.pathname.slice(1)]);
                
                const exists = readRoles.some(p => {
                    return p.targetURN === object[0].id
                });
                
                if(!exists){
                    return res.status(403).send("Forbidden");
                }
            }
        }

        return res.header('X-Lake-Root', lakeMetadata[0][0].path).send('ok');
    } catch (err) {
        return res.status(403).send("Forbidden");
    }
}