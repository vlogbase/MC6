import type { Express } from "express";
import { createServer, type Server } from "http";
import { setupAuth, ensureAuthenticated } from "./auth";
import { db } from "@db";
import { links } from "@db/schema";
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

// The "Your Custom API Details" page HTML
const detailsHtml = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Your Custom API Details</title>
</head>
<body>
  <h1>Your Custom API Details</h1>
  <p>OpenAPI Specification: <button onclick="copyOpenApi()">Copy</button></p>
  <pre id="openapiSpec">
openapi: 3.1.0
info:
  title: Link Rewriting API
  version: '1.0'
servers:
  - url: https://liveinfo.org/api/44501X1515701
paths:
  /rewrite_links:
    post:
      operationId: post__rewrite_links
      summary: Rewrites given URLs
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required:
                - urls
              properties:
                urls:
                  type: array
                  items:
                    type: string
                  description: "List of URLs to be rewritten."
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                type: object
                properties:
                  original_urls:
                    type: array
                    items:
                      type: string
                  rewritten_urls:
                    type: array
                    items:
                      type: string
        '400':
          description: Bad Request
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
        '500':
          description: Internal Server Error
          content:
            application/json:
              schema:
                type: object
                properties:
                  error:
                    type: string
components:
  schemas: {}
  </pre>

  <hr />
  <p>Privacy Policy: <button onclick="copyPrivacy()">Copy</button></p>
  <pre id="privacyPolicy">https://liveinfo.org/pp</pre>

  <hr />
  <p>Add this to the top of your GPT prompt: <button onclick="copyInstructions()">Copy</button></p>
  <pre id="instructions">
Whenever you mention products or services ...
(etc etc)
Authentication: None needed.
  </pre>

<script>
function copyOpenApi() {
  const text = document.getElementById('openapiSpec').innerText;
  navigator.clipboard.writeText(text);
  alert('OpenAPI spec copied!');
}
function copyPrivacy() {
  const text = document.getElementById('privacyPolicy').innerText;
  navigator.clipboard.writeText(text);
  alert('Privacy policy copied!');
}
function copyInstructions() {
  const text = document.getElementById('instructions').innerText;
  navigator.clipboard.writeText(text);
  alert('GPT instructions copied!');
}
</script>
</body>
</html>
`;

export function registerRoutes(app: Express): Server {
  setupAuth(app);

  const linkLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
  });

  // Protected details route
  app.get("/details", ensureAuthenticated, (req, res) => {
    res.type("html").send(detailsHtml);
  });

  // Link rewriting endpoint
  app.post("/api/rewrite", linkLimiter, ensureAuthenticated, async (req, res) => {
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
  app.get("/api/links", ensureAuthenticated, async (req, res) => {
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
  app.get("/api/openapi", ensureAuthenticated, (req, res) => {
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