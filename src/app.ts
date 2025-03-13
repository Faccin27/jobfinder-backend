import Fastify, { FastifyReply, FastifyRequest } from "fastify";
import cors from "@fastify/cors";
import jwt from "@fastify/jwt";
import cookie from "@fastify/cookie";
import "dotenv/config"
import router from './routes/router'

const app = Fastify({ logger: true });

// Configuração de Cookies
app.register(cookie);


// Configuração do CORS
app.register(cors, {
  origin: "http://localhost:3000", // Permitir requisições do front-end
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"], // Métodos permitidos
  allowedHeaders: ["Content-Type", "Authorization"], // Cabeçalhos permitidos
  credentials: true, // Permitir credenciais (cookies, auth headers)
});

// Configuração do JWT
app.register(jwt, {
  secret: process.env.JWT_SECRET || "Secret_key",
  cookie: {
    cookieName: "token",
    signed: false,
  },
});

// Middleware de Autenticação
app.decorate("authenticate", async function (request: FastifyRequest, reply: FastifyReply) {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.status(401).send({ error: "Unauthorized" });
  }
});

app.register(router);

export default app;
