import { FastifyInstance } from "fastify";
import cloudinaryController from "../controllers/cloudinaryController";

export default async function userRoutes(app: FastifyInstance) {
  app.get("/images", cloudinaryController.listImages);
  app.delete("/images/:publicId", cloudinaryController.deleteImage);
  app.post("/images", cloudinaryController.uploadImage);
}
