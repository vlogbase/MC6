import type { Express } from "express";
import { createServer, type Server } from "http";
import { setupAuth, authenticateRequest } from "./auth";
import { db } from "@db";
import { links, users } from "@db/schema";
import { eq, and } from "drizzle-orm";
import rateLimit from "express-rate-limit";

// In-memory caching (just as you had before)
const linkCache = new Map<string, { rewrittenUrl: string; timestamp: number }>();
const CACHE_TTL = 1000 * 60 * 60; // 1 hour

function generateCacheKey(userId: number, url: string, source: string) {
  return `${userId}:${url}:${source}`;
}

function getCachedLink(cacheKey: string) {
  const cached = linkCache.get(cacheKey);
  if (!cached) return null;

  // Expired?
  if (Date.now() - cached.timestamp > CACHE_TTL) {
    linkCache.delete(cacheKey);
    return null;
  }
  return cached.rewrittenUrl;
}

export function registerRoutes(app: Express): Server {
  // Setup OAuth flow
  setupAuth(app);

  const linkLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
  });

  // Rewriting route – now uses only OAuth
  app.post("/api/rewrite", linkLimiter, authenticateRequest, async (req, res) => {
    const userId = req.oauthToken?.userId;
    if (!userId) {
      return res.status(401).json({ error: "User not authenticated" });
    }

    const { url, source } = req.body;
    if (!url || !source) {
      return res.status(400).json({ error: "URL and source are required" });
    }

    const cacheKey = generateCacheKey(userId, url, source);
    const cached = getCachedLink(cacheKey);
    if (cached) {
      return res.json({ rewrittenUrl: cached });
    }

    try {
      // Check if link already exists in DB
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
          timestamp: Date.now(),
        });
        return res.json({ rewrittenUrl: existingLink.rewrittenUrl });
      }

      // Otherwise, fetch user to get SSID
      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.id, userId))
        .limit(1);

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      // Construct the affiliate link
      const rewrittenUrl = `${url}?ssid=${user.ssid}&source=${encodeURIComponent(
        source
      )}`;

      // Insert new link record
      await db.insert(links).values({
        userId,
        originalUrl: url,
        rewrittenUrl,
        source,
      });

      // Cache it
      linkCache.set(cacheKey, {
        rewrittenUrl,
        timestamp: Date.now(),
      });

      return res.json({ rewrittenUrl });
    } catch (error) {
      console.error("Error rewriting link:", error);
      return res.status(500).json({ error: "Failed to rewrite link" });
    }
  });

  // The openapi route is unchanged
  app.get("/api/openapi", (req, res) => {
    const spec = {
      openapi: "3.1.0",
      info: {
        title: "Link Rewriting API",
        version: "1.0",
        description: "API for rewriting links with affiliate tracking",
      },
      servers: [
        {
          url: `${req.protocol}://${req.get("host")}`,
        },
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
                      url: { type: "string" },
                      source: { type: "string" },
                    },
                  },
                },
              },
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
                        },
                      },
                    },
                  },
                },
              },
            },
          },
        },
      },
      components: {
        securitySchemes: {
          OAuth2: {
            type: "oauth2",
            flows: {
              clientCredentials: {
                tokenUrl: "/api/auth",
                scopes: {
                  rewrite: "Rewrite URLs with affiliate tracking",
                },
              },
            },
          },
        },
      },
    };
    res.json(spec);
  });

  const httpServer = createServer(app);
  return httpServer;
}
