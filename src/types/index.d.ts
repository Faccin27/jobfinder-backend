import 'fastify';

declare module 'fastify' {
  interface FastifyRequest {
    user: {
      id: string;
      name: string;        
      email: string;
      role: 'CLIENTE' | 'PRESTADOR' | 'ADMIN';  
      picture?: string;   
      job?: string;        
      createdAt: Date;
    }
  }
}