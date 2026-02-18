import { getPubKey } from "../Utils.js";
import jwt from "jsonwebtoken";

export async function authMiddlewareUser(req, res) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).send({ error: "Missing or invalid Authorization header" });
    }

    const token = authHeader.split(" ")[1];

    const pubKey = await getPubKey();

    const decoded = jwt.verify(token, pubKey, {
      algorithms: ["RS256"],
    });

    req.iamData = decoded;
  } catch (err) {
    return res.status(401).send({ error: "Invalid or expired token" });
  }
}