import { FastifyInstance } from "fastify";
import {
  registerUser,
  getUserData,
  getUserById,
  getAllUsers
} from "../controllers/userController";

export default async function userRoutes(app: FastifyInstance) {
  app.post("/register", registerUser);

  // app.get('/me', {preHandler: [app.authenticate]}, getUserData)
  app.get("/:id", getUserById);
  app.get("/", getAllUsers)
}
