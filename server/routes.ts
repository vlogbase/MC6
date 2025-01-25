import type { Express } from "express";
import { createServer, type Server } from "http";
import { setupAuth } from "./auth";

export async function registerRoutes(app: Express): Promise<Server> {
  // Setup OAuth and auth routes
  setupAuth(app);

  // Create and return HTTP server
  const httpServer = createServer(app);
  return httpServer;
}