import type { Express } from "express";
import { createServer, type Server } from "http";
import { setupAuth, authenticateRequest } from "./auth";
import { db } from "@db";
import { links, users } from "@db/schema"; // Added users import
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

  // Link rewriting endpoint - now supports both session and OAuth auth
  app.post("/api/rewrite", linkLimiter, authenticateRequest, async (req, res) => {
    // Get userId either from session or OAuth token
    const userId = req.oauthToken?.userId || req.user?.id;

    if (!userId) {
      return res.status(401).json({ error: "User not authenticated" });
    }

    const { url, source } = req.body;
    if (!url || !source) {
      return res.status(400).json({ error: "URL and source are required" });
    }

    const cacheKey = generateCacheKey(userId, url, source);
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
            eq(links.userId, userId),
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

      // Generate the rewritten URL with the user's SSID
      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, userId))
        .limit(1);

      const rewrittenUrl = `${url}?ssid=${user.ssid}&source=${encodeURIComponent(source)}`;

      // Store the new link
      const [newLink] = await db
        .insert(links)
        .values({
          userId,
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
      res.status(500).json({ error: "Failed to rewrite link" });
    }
  });

  // OpenAPI spec endpoint - no auth required
  app.get("/api/openapi", (req, res) => {
    const spec = {
      openapi: "3.1.0",
      info: {
        title: "Link Rewriting API",
        version: "1.0",
        description: "API for rewriting links with affiliate tracking"
      },
      servers: [
        {
          url: `${req.protocol}://${req.get('host')}`
        }
      ],
      paths: {
        "/api/rewrite": {
          post: {
            operationId: "rewriteUrl",
            summary: "Rewrite a URL with affiliate information",
            security: [{ OAuth2: ["rewrite"] }],
            requestBody: {
              required: true,
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["url", "source"],
                    properties: {
                      url: {
                        type: "string",
                        description: "The URL to rewrite"
                      },
                      source: {
                        type: "string",
                        description: "Source identifier"
                      }
                    }
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
                          description: "The rewritten URL with affiliate parameters"
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      },
      components: {
        securitySchemes: {
          OAuth2: {
            type: "oauth2",
            flows: {
              clientCredentials: {
                tokenUrl: "/api/auth",
                scopes: {
                  rewrite: "Rewrite URLs with affiliate tracking"
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