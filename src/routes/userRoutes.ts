import { FastifyInstance } from "fastify";
import {
  registerUser,
  getUserData,
  getUserById,
  getAllUsers,
  login,
  getLoggedUser,
  logout,
  updateUser,
  getUsersByJob
} from "../controllers/userController";

export default async function userRoutes(app: FastifyInstance) {
  // Rotas estáticas
  app.post("/register", registerUser);
  app.post("/login", login);
  app.post("/logout", logout);
  app.get("/", getAllUsers);
  app.get("/by-job", getUsersByJob)
  app.get("/me", getLoggedUser);
  app.put("/update", updateUser);
  // app.get('/me', {preHandler: [app.authenticate]}, getUserData)

  // Rotas dinâmicas abaixo
  app.get("/:id", getUserById);
}
