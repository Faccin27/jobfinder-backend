import { FastifyInstance } from "fastify";
import userRoutes from "./userRoutes";
import cloudinaryRoutes from "./cloudinaryRoutes";

export default async function router(app: FastifyInstance) {
  await app.register(userRoutes, { prefix: "/users" });
  await app.register(cloudinaryRoutes, { prefix: "/assets" });
}
