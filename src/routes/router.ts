import { FastifyInstance } from "fastify";
import userRoutes from './userRoutes';

export default async function router(app: FastifyInstance) {
  await app.register(userRoutes, { prefix: '/users' }); 
}