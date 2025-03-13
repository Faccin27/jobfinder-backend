import { FastifyReply, FastifyRequest } from 'fastify';
import { prisma } from '../prisma/Client';
import bcrypt from 'bcryptjs';
import { z } from 'zod';


// Função para registrar um usuário
export const registerUser = async (request: FastifyRequest, reply: FastifyReply) => {
  const schema = z.object({
    name: z.string(),
    email: z.string().email(),
    password: z.string().min(6),
    role: z.enum(['CLIENTE', 'PRESTADOR', 'ADMIN']).default('CLIENTE'),
    picture: z.string().optional(),
    job: z.string().optional(),
  });

  const { name, email, password, role, picture, job } = schema.parse(request.body);

  // Verifica se apenas prestadores podem ter job
  if (role !== 'PRESTADOR' && job) {
    return reply.status(400).send({ message: 'Apenas prestadores podem ter job.' });
  }

  // Criptografa a password
  const hashedpassword = await bcrypt.hash(password, 10);

  try {
    const user = await prisma.user.create({
      data: { name, email, password: hashedpassword, role, picture, job },
    });

    return reply.status(201).send(user);
  } catch (error) {
    return reply.status(500).send({ message: 'Erro ao criar usuário.' });
  }
};

// Função para buscar dados do usuário autenticado
export const getUserData = async (request: FastifyRequest, reply: FastifyReply) => {
    const userId = (request.user as {id: string}).id;
    
    try {
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { name: true, email: true, role: true, picture: true, job: true, createdAt: true },
      });
  
      if (!user) {
        return reply.status(404).send({ message: 'Usuário não encontrado.' });
      }
  
      return reply.send(user);
    } catch (error) {
      return reply.status(500).send({ message: 'Erro ao buscar dados do usuário.' });
    }
  };

  export const getUserById = async (request: FastifyRequest<{
    Params: { id: string }
  }>, reply: FastifyReply) => {
    try {
      const id = String(request.params.id);
      const user = await prisma.user.findUnique({
        where: { id }, 
        select: { name: true, email: true, role: true, picture: true, job: true, createdAt: true },
      });
  
      if (!user) {
        return reply.status(404).send({ message: 'Usuário não encontrado.' });
      }
  
      return reply.send(user);
    } catch (error) {
      return reply.status(500).send({ message: 'Erro ao buscar dados do usuário.' });
    }
  };