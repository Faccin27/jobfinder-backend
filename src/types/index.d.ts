import 'fastify';

declare module 'fastify' {
  interface FastifyRequest {
    user: {
      id: number;
      name: string;        
      email: string;
      role: 'CLIENTE' | 'PRESTADOR' | 'ADMIN';  
      picture?: string;   
      job?: string;        
      createdAt: Date;
    }
  }
}