import type { Express } from "express";
import { createServer, type Server } from "http";
import axios from "axios";
import { db } from "@db";
import { links } from "@db/schema";
import { eq } from "drizzle-orm";
import { setupAuth, authenticateRequest } from "./auth";

// In-memory cache for rewriting
const urlCache = new Map<
  string, // `${userId}:${originalUrl}:${source}`
  {
    rewrittenUrl: string;
    timestamp: number;
  }
>();
const CACHE_TTL = 3600000; // 1 hour in ms

async function getRewrittenUrl(
  originalUrl: string,
  userId: number,
  source: string
): Promise<string> {
  const cacheKey = `${userId}:${originalUrl}:${source}`;
  const cached = urlCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.rewrittenUrl;
  }

  // Not in cache => call Strackr
  try {
    const resp = await axios.get("https://api.strackr.com/v3/tools/linkbuilder", {
      params: {
        api_id: process.env.STRACKR_API_ID,
        api_key: process.env.STRACKR_API_KEY,
        url: originalUrl,
      },
    });
    const data = resp.data;
    let trackingLink: string | undefined;
    const [first] = data.results || [];
    if (first?.advertisers?.length) {
      const adv = first.advertisers[0];
      if (adv.connections?.length) {
        const conn = adv.connections[0];
        if (conn.links?.length) {
          trackingLink = conn.links[0].trackinglink;
        }
      }
    }
    if (!trackingLink) throw new Error("No tracking link found from Strackr");

    // Store in in-memory cache
    urlCache.set(cacheKey, { rewrittenUrl: trackingLink, timestamp: Date.now() });

    // Also store in DB if you want them visible to user #1 or something
    await db.insert(links).values({
      userId,
      originalUrl,
      rewrittenUrl: trackingLink,
      source,
    });

    return trackingLink;
  } catch (error: any) {
    console.error("Strackr linkbuilder error:", error?.message || error);
    throw error;
  }
}

async function fetchStrackrStats(endpoint: string, params: Record<string, string>) {
  const resp = await axios.get(`https://api.strackr.com/v3/${endpoint}`, {
    params: {
      api_id: process.env.STRACKR_API_ID,
      api_key: process.env.STRACKR_API_KEY,
      ...params,
    },
  });
  return resp.data;
}

export function registerRoutes(app: Express): Server {
  // Set up local+token auth
  setupAuth(app);

  /**
   * GPT endpoints => require Bearer token, but NOT local user session
   * We'll do a minimal check:
   *    if (req.oauthToken) => allow
   *    else => 401
   *
   * If you want them fully open, remove the check.
   */
  app.post("/api/rewrite", (req, res) => {
    // Check that there's a valid token
    if (!req.oauthToken) {
      return res.status(401).json({ error: "Missing or invalid Bearer token" });
    }

    const { url, source } = req.body;
    if (!url || !source) {
      return res.status(400).json({ error: "url and source are required" });
    }

    // e.g. store them under userId=1 in DB, or userId= req.oauthToken.userId
    // We'll use oauthToken.userId so if you minted that token for user=1, it’s 1 anyway
    const userId = req.oauthToken.userId || 1;

    getRewrittenUrl(url, userId, source)
      .then((rewrittenUrl) => res.json({ rewrittenUrl }))
      .catch((err: any) => {
        console.error("Rewrite error:", err);
        res.status(500).json({
          error: "Failed to rewrite link",
          message: err?.message || String(err),
        });
      });
  });

  app.get("/api/stats/:type", (req, res) => {
    // Also require token or open it if you want
    if (!req.oauthToken) {
      return res.status(401).json({ error: "Missing or invalid Bearer token" });
    }
    const { type } = req.params;
    const { timeStart, timeEnd } = req.query as { [key: string]: string };
    if (!timeStart || !timeEnd) {
      return res.status(400).json({ error: "timeStart and timeEnd are required" });
    }

    const endpoint = `reports/${type}`;
    fetchStrackrStats(endpoint, {
      time_start: timeStart,
      time_end: timeEnd,
      time_type: "checked",
    })
      .then((data) => res.json(data))
      .catch((err) => {
        console.error(`Stats error for ${type}:`, err);
        res.status(500).json({
          error: `Failed to fetch ${type} stats`,
          message: err?.message || String(err),
        });
      });
  });

  /**
   * Protected endpoints for your local users:
   * e.g. /api/links => must have user session or valid token
   */
  app.get("/api/links", authenticateRequest, async (req, res) => {
    try {
      const userId = req.user?.id || req.oauthToken?.userId;
      if (!userId) {
        return res.status(401).json({ error: "No user found in session or token" });
      }
      const userLinks = await db
        .select()
        .from(links)
        .where(eq(links.userId, userId))
        .orderBy(links.createdAt);
      res.json(userLinks);
    } catch (error) {
      console.error("Error fetching links:", error);
      res.status(500).json({ error: "Failed to fetch links" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
