import { FastifyReply, FastifyRequest } from "fastify";
import { prisma } from "../prisma/Client";
import bcrypt from "bcryptjs";
import { z } from "zod";

// Função para registrar um usuário
export const registerUser = async (
  request: FastifyRequest,
  reply: FastifyReply
) => {
  const schema = z.object({
    name: z.string(),
    email: z.string().email(),
    password: z.string().min(6),
    role: z.enum(["CLIENTE", "PRESTADOR", "ADMIN"]).default("CLIENTE"),
    picture: z.string().optional(),
    job: z.string().optional(),
  });

  const { name, email, password, role, picture, job } = schema.parse(
    request.body
  );

  // Verifica se apenas prestadores podem ter job
  if (role !== "PRESTADOR" && job) {
    return reply
      .status(400)
      .send({ message: "Apenas prestadores podem ter job." });
  }

  // Criptografa a password
  const hashedpassword = await bcrypt.hash(password, 10);

  try {
    const user = await prisma.user.create({
      data: { name, email, password: hashedpassword, role, picture, job },
    });

    return reply.status(201).send(user);
  } catch (error) {
    return reply.status(500).send({ message: "Erro ao criar usuário." });
  }
};

// Função para buscar dados do usuário autenticado
export const getUserData = async (
  request: FastifyRequest,
  reply: FastifyReply
) => {
  const userId = (request.user as { id: number }).id;

  try {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        name: true,
        email: true,
        role: true,
        picture: true,
        job: true,
        createdAt: true,
      },
    });

    if (!user) {
      return reply.status(404).send({ message: "Usuário não encontrado." });
    }

    return reply.send(user);
  } catch (error) {
    return reply
      .status(500)
      .send({ message: "Erro ao buscar dados do usuário." });
  }
};

export const getUserById = async (
  request: FastifyRequest<{
    Params: { id: number };
  }>,
  reply: FastifyReply
) => {
  try {
    // Usar Number() para garantir que o ID seja convertido para número
    const id = Number(request.params.id);

    // Verifica se o ID foi convertido corretamente
    if (isNaN(id)) {
      return reply.status(400).send({ message: "ID inválido." });
    }

    const user = await prisma.user.findUnique({
      where: { id },
      select: {
        name: true,
        email: true,
        role: true,
        picture: true,
        job: true,
        createdAt: true,
      },
    });

    if (!user) {
      return reply.status(404).send({ message: "Usuário não encontrado." });
    }

    return reply.send(user);
  } catch (error) {
    return reply
      .status(500)
      .send({ message: "Erro ao buscar dados do usuário." });
  }
};

export const getAllUsers = async (
  request: FastifyRequest,
  reply: FastifyReply
) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        picture: true,
        job: true,
        createdAt: true,
      },
    });

    return reply.send(users);
  } catch (error) {
    return reply.status(500).send({ message: "Erro ao buscar usuários." });
  }
};

interface loginRequest {
  Body: {
    email: string;
    password: string;
  };
}

export const login = async (
  request: FastifyRequest<{ Body: { email: string; password: string } }>,
  reply: FastifyReply
) => {
  const { email, password } = request.body;
  try {
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return reply.status(404).send({ message: "Credenciais inválidas." });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return reply.status(401).send({ message: "Credenciais inválidas." });
    }

    // Gerando o token JWT
    const token = await reply.jwtSign(
      { id: user.id, email: user.email },
      { expiresIn: "1h" }
    );

    // Salva token cookie HTTP-only
    reply.setCookie("token", token, {
      httpOnly: true, // Protege contra XSS
      secure: false, // Em produção, mude para true (apenas HTTPS)
      sameSite: "strict", // Protege contra CSRF
      path: "/", // Disponível em todas as rotas do site
      maxAge: 60 * 60, // Expira em 1 hora (segundos)
    });

    return reply.send({ message: "Login bem-sucedido" });
  } catch (error) {
    console.error(error);
    reply.status(500).send({ message: "Erro ao fazer login." });
  }
};

interface JwtPayload {
  id: number; 
  email: string;
}

export const getLoggedUser = async (
  request: FastifyRequest,
  reply: FastifyReply
) => {
  try {
    const decodedToken = await request.jwtVerify<JwtPayload>(); 

    const userIdFromToken = decodedToken.id; 
    
    const user = await prisma.user.findUnique({
      where: { id: userIdFromToken },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        picture: true,
        job: true,
        createdAt: true,
      },
    });

    if (!user) {
      return reply.status(404).send({ message: "Usuário não encontrado" });
    }

    reply.send(user);
  } catch (error) {
    reply.status(401).send({ message: "Token inválido ou expirado" });
  }
};
