import type { Express } from "express";
import { createServer, type Server } from "http";
import { setupAuth } from "./auth";
import { db } from "@db";
import { links, insertLinkSchema } from "@db/schema";
import { eq } from "drizzle-orm";
import rateLimit from "express-rate-limit";

export function registerRoutes(app: Express): Server {
  setupAuth(app);

  const linkLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
  });

  // Link management endpoints
  app.post("/api/links", linkLimiter, async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).send("Not logged in");
    }

    const result = insertLinkSchema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).send(result.error.message);
    }

    try {
      const [link] = await db.insert(links)
        .values({
          ...result.data,
          userId: req.user.id
        })
        .returning();
      
      res.json(link);
    } catch (error) {
      res.status(500).send("Failed to create link");
    }
  });

  app.get("/api/links", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).send("Not logged in");
    }

    try {
      const userLinks = await db.select()
        .from(links)
        .where(eq(links.userId, req.user.id))
        .orderBy(links.createdAt);
      
      res.json(userLinks);
    } catch (error) {
      res.status(500).send("Failed to fetch links");
    }
  });

  // OpenAPI spec endpoint
  app.get("/api/openapi", (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).send("Not logged in");
    }

    const spec = {
      openapi: "3.0.0",
      info: {
        title: "Link Rewriting API",
        version: "1.0.0",
        description: `API for rewriting links with SSID: ${req.user.ssid}`
      },
      servers: [
        {
          url: `${req.protocol}://${req.get("host")}`
        }
      ],
      paths: {
        "/api/rewrite": {
          post: {
            summary: "Rewrite a URL with affiliate information",
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      url: {
                        type: "string",
                        description: "The URL to rewrite"
                      },
                      source: {
                        type: "string",
                        description: "Source identifier"
                      }
                    },
                    required: ["url", "source"]
                  }
                }
              }
            },
            responses: {
              "200": {
                description: "Successfully rewritten URL",
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      properties: {
                        url: {
                          type: "string",
                          description: "The rewritten URL"
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    };

    res.json(spec);
  });

  const httpServer = createServer(app);
  return httpServer;
}
