import Fastify from 'fastify';
import multipart from '@fastify/multipart';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import { ObjectMetadata, PutObject } from './routes/object.js';
import { CreateLake } from './routes/lake.js';
import { AssociateDNS, CheckOwner, ValidatePermissions } from './routes/security.js';
import { authMiddlewareUser } from './Middlewares/Client.js';
dotenv.config();

const fastify = Fastify();

const connection = await mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD
});

fastify.decorate("db", connection);

await fastify.register(multipart, {
  limits: { fileSize: 1000 * 1024 * 1024 },
});

const SFTP_CONFIG = {
  host: process.env.SFTP_HOST,
  port: Number(process.env.SFTP_PORT),
  username: process.env.SFTP_USER,
  password: process.env.SFTP_PASS
};

fastify.post('/fileUpload/:lakeId', { preHandler: fastify.multipart }, async (req, res) => { return PutObject(req, res, SFTP_CONFIG); });
fastify.post('/createLake', { preHandler: authMiddlewareUser }, (req, res) => { return CreateLake(req, res, SFTP_CONFIG); });
fastify.post('/attachDomain', { preHandler: authMiddlewareUser }, AssociateDNS);
fastify.get('/object/:objectId', ObjectMetadata);
fastify.get('/objectPermission', ValidatePermissions);
fastify.get('/checkOwner', CheckOwner);

await fastify.listen({ host: '127.0.0.1', port: 8080 });