import { FastifyInstance } from "fastify";
import {
  registerUser,
  getUserData,
  getUserById,
  getAllUsers,
  login,
  getLoggedUser
} from "../controllers/userController";

export default async function userRoutes(app: FastifyInstance) {
  // Rotas estáticas
  app.post("/register", registerUser);
  app.post("/login", login)
  app.get("/s", getAllUsers);
  app.get("/me", getLoggedUser);
  // app.get('/me', {preHandler: [app.authenticate]}, getUserData)
  
  // Rotas dinâmicas abaixo
  app.get("/:id", getUserById);
}