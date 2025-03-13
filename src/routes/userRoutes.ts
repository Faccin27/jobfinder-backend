import { FastifyInstance } from "fastify";
import {
  registerUser,
  getUserData,
  getUserById,
  getAllUsers
} from "../controllers/userController";

export default async function userRoutes(app: FastifyInstance) {
  // Rotas estáticas
  app.post("/register", registerUser);
  app.get("/", getAllUsers);
  // app.get('/me', {preHandler: [app.authenticate]}, getUserData)
  
  // Rotas dinâmicas abaixo
  app.get("/:id", getUserById);
}