import Fastify from 'fastify';
import multipart from '@fastify/multipart';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import { DeleteObject, MoveObject, ObjectMetadata, PutObject, RenameObject } from './routes/object.js';
import { CreateLake } from './routes/lake.js';
import { AssociateDNS, CheckOwner, ValidatePermissions } from './routes/security.js';
import { authMiddlewareUser } from './Middlewares/Client.js';
import { CreateFolder, DeleteFolder, MoveFolder, RenameFolder } from './routes/folders.js';
import { AbortMultipart, CompletePartsUpload, CreateMultipart, GetMissingParts, UploadPart } from './routes/multipart.js';
dotenv.config();

const fastify = Fastify();

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

fastify.decorate("db", pool);

await fastify.register(multipart, {
  limits: { fileSize: 20 * 1024 * 1024 },
});

const SFTP_CONFIG = {
  host: process.env.SFTP_HOST,
  port: Number(process.env.SFTP_PORT),
  username: process.env.SFTP_USER,
  password: process.env.SFTP_PASS
};

fastify.post('/fileUpload', { preHandler: fastify.multipart }, async (req, res) => { return PutObject(req, res, SFTP_CONFIG); });
fastify.post('/uploadPart', { preHandler: fastify.multipart }, async (req, res) => { return UploadPart(req, res, SFTP_CONFIG); });
fastify.post('/createLake', { preHandler: authMiddlewareUser }, (req, res) => { return CreateLake(req, res, SFTP_CONFIG); });
fastify.post('/createFolder', { preHandler: authMiddlewareUser }, (req, res) => { return CreateFolder(req, res, SFTP_CONFIG); });
fastify.delete('/deleteFolder', { preHandler: authMiddlewareUser }, (req, res) => { return DeleteFolder(req, res, SFTP_CONFIG); });
fastify.delete('/deleteObject', { preHandler: authMiddlewareUser }, (req, res) => { return DeleteObject(req, res, SFTP_CONFIG); });
fastify.post('/renameFolder', { preHandler: authMiddlewareUser }, (req, res) => { return RenameFolder(req, res, SFTP_CONFIG); });
fastify.post('/renameObject', { preHandler: authMiddlewareUser }, (req, res) => { return RenameObject(req, res, SFTP_CONFIG); });
fastify.post('/moveObject', { preHandler: authMiddlewareUser }, (req, res) => { return MoveObject(req, res, SFTP_CONFIG); });
fastify.post('/moveFolder', { preHandler: authMiddlewareUser }, (req, res) => { return MoveFolder(req, res, SFTP_CONFIG); });
fastify.post('/attachDomain', { preHandler: authMiddlewareUser }, AssociateDNS);
fastify.post('/missingParts', { preHandler: authMiddlewareUser }, GetMissingParts);
fastify.post('/completeMultipart', { preHandler: authMiddlewareUser }, CompletePartsUpload);
fastify.delete('/abortMultipart', { preHandler: authMiddlewareUser }, AbortMultipart);
fastify.get('/object/:objectId', ObjectMetadata);
fastify.get('/objectPermission', ValidatePermissions);
fastify.post('/createMultipart', { preHandler: authMiddlewareUser }, CreateMultipart);
fastify.get('/checkOwner', CheckOwner);

await fastify.listen({ host: '127.0.0.1', port: 8080 });