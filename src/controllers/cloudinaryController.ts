import { FastifyReply, FastifyRequest } from "fastify";
import { MultipartFile } from "@fastify/multipart";
const cloudinary = require("cloudinary").v2;
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import "dotenv/config";

// Cloudinary configuration
cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Type definitions for Cloudinary responses
interface CloudinaryUploadResult {
  secure_url: string;
  public_id: string;
  result?: string;
  [key: string]: any;
}

interface CloudinaryListResult {
  resources: Array<{
    public_id: string;
    url: string;
    secure_url: string;
    created_at: string;
    format: string;
    [key: string]: any;
  }>;
  [key: string]: any;
}

// Request params interfaces
interface DeleteImageParams {
  publicId: string;
}

class CloudinaryController {
  // Upload image
  async uploadImage(
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<FastifyReply> {
    try {
      const data = (await request.file()) as MultipartFile;

      if (!data) {
        return reply.status(400).send({ message: "No file uploaded" });
      }

      // Read file as buffer
      const fileBuffer = await data.toBuffer();

      const result = (await cloudinary.v2.uploader.upload(
        `data:${data.mimetype};base64,${fileBuffer.toString("base64")}`,
        {
          folder: process.env.CLOUDINARY_FOLDER,
          filename: data.filename,
        }
      )) as CloudinaryUploadResult;

      return reply.send({
        message: "Image uploaded successfully!",
        url: result.secure_url,
        public_id: result.public_id,
      });
    } catch (error) {
      console.error("Upload error:", error);
      return reply.status(500).send({
        error: "Internal Server Error",
        details: (error as Error).message,
      });
    }
  }

  // Delete image by publicId
  async deleteImage(
    request: FastifyRequest<{
      Params: DeleteImageParams;
    }>,
    reply: FastifyReply
  ): Promise<FastifyReply> {
    try {
      const { publicId } = request.params;

      if (!publicId) {
        return reply.status(400).send({ message: "No public ID provided" });
      }

      const result = (await cloudinary.v2.uploader.destroy(
        publicId
      )) as CloudinaryUploadResult;

      if (result.result === "ok") {
        return reply.send({ message: "Image deleted successfully!" });
      } else {
        return reply.status(404).send({ message: "Image not found" });
      }
    } catch (error) {
      console.error(error);
      return reply.status(500).send({ error: "Internal Server Error" });
    }
  }

  // List images from a folder
  async listImages(
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<FastifyReply> {
    try {
      const result = (await cloudinary.v2.api.resources({
        type: "upload",
        prefix: process.env.CLOUDINARY_FOLDER,
        max_results: 10,
      })) as CloudinaryListResult;

      return reply.send(result.resources);
    } catch (error) {
      console.error(error);
      return reply.status(500).send({ error: "Internal Server Error" });
    }
  }
}

export = new CloudinaryController();
