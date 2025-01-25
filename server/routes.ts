import type { Express } from "express";
import { createServer, type Server } from "http";
import { setupAuth } from "./auth";
import { db } from "@db";
import { links, insertLinkSchema } from "@db/schema";
import { eq, and } from "drizzle-orm";
import rateLimit from "express-rate-limit";

// In-memory cache using LRU approach
const linkCache = new Map<string, { rewrittenUrl: string, timestamp: number }>();
const CACHE_TTL = 1000 * 60 * 60; // 1 hour in milliseconds

function generateCacheKey(userId: number, url: string, source: string) {
  return `${userId}:${url}:${source}`;
}

function getCachedLink(cacheKey: string) {
  const cached = linkCache.get(cacheKey);
  if (cached) {
    if (Date.now() - cached.timestamp < CACHE_TTL) {
      return cached.rewrittenUrl;
    }
    linkCache.delete(cacheKey);
  }
  return null;
}

export function registerRoutes(app: Express): Server {
  setupAuth(app);

  const linkLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
  });

  // Link rewriting endpoint
  app.post("/api/rewrite", linkLimiter, async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).send("Not logged in");
    }

    const { url, source } = req.body;
    if (!url || !source) {
      return res.status(400).send("URL and source are required");
    }

    const cacheKey = generateCacheKey(req.user.id, url, source);
    const cachedUrl = getCachedLink(cacheKey);

    if (cachedUrl) {
      return res.json({ rewrittenUrl: cachedUrl });
    }

    try {
      // Check if we already have this link in the database
      const [existingLink] = await db
        .select()
        .from(links)
        .where(
          and(
            eq(links.userId, req.user.id),
            eq(links.originalUrl, url),
            eq(links.source, source)
          )
        )
        .limit(1);

      if (existingLink) {
        linkCache.set(cacheKey, {
          rewrittenUrl: existingLink.rewrittenUrl,
          timestamp: Date.now()
        });
        return res.json({ rewrittenUrl: existingLink.rewrittenUrl });
      }

      // In a real implementation, this would call the Strackr API
      // For now, we'll simulate by appending the SSID and source
      const rewrittenUrl = `${url}?ssid=${req.user.ssid}&source=${encodeURIComponent(source)}`;

      // Store the new link
      const [newLink] = await db
        .insert(links)
        .values({
          userId: req.user.id,
          originalUrl: url,
          rewrittenUrl,
          source,
        })
        .returning();

      // Cache the result
      linkCache.set(cacheKey, {
        rewrittenUrl,
        timestamp: Date.now()
      });

      res.json({ rewrittenUrl });
    } catch (error) {
      console.error('Error rewriting link:', error);
      res.status(500).send("Failed to rewrite link");
    }
  });

  // Links listing endpoint
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
            security: [{ cookieAuth: [] }],
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
                        rewrittenUrl: {
                          type: "string",
                          description: "The rewritten URL with SSID and source parameters"
                        }
                      }
                    }
                  }
                }
              },
              "401": {
                description: "Not authenticated"
              },
              "400": {
                description: "Invalid input"
              },
              "500": {
                description: "Server error"
              }
            }
          }
        },
        "/api/links": {
          get: {
            summary: "Get all links for the user",
            security: [{cookieAuth: []}],
            responses: {
              "200": {
                description: "List of links"
              },
              "401": {
                description: "Not authenticated"
              },
              "500": {
                description: "Server error"
              }
            }
          }
        }
      },
      components: {
        securitySchemes: {
          cookieAuth: {
            type: "apiKey",
            in: "cookie",
            name: "connect.sid"
          }
        }
      }
    };

    res.json(spec);
  });

  const httpServer = createServer(app);
  return httpServer;
}