import type { Express } from "express";
import { createServer, type Server } from "http";
import axios from "axios";
import { db } from "@db";
import { links, users } from "@db/schema";
import { eq } from "drizzle-orm";
import { setupAuth, authenticateRequest } from "./auth";

// In-memory cache for rewriting
const urlCache = new Map<
  string,
  {
    rewrittenUrl: string;
    timestamp: number;
  }
>();
const CACHE_TTL = 3600000; // 1 hour in ms

/**
 * getRewrittenUrl:
 * 1. Checks if the link is in the cache and still valid.
 * 2. If not, calls Strackr’s link builder endpoint, including a custom user‑agent header.
 * 3. Returns the base tracking link.
 */
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
      headers: {
        // Identify the request as coming from your app.
        "User-Agent": "MonetizeChatbots/1.0",
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

    // Store base tracking link in cache
    urlCache.set(cacheKey, { rewrittenUrl: trackingLink, timestamp: Date.now() });

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
  setupAuth(app);

  // GPT endpoints - API key auth only
  app.post("/api/rewrite", async (req, res) => {
    const apiKey = req.headers["x-api-key"];
    if (!apiKey) {
      return res.status(401).json({ error: "Missing X-API-KEY header" });
    }

    // Find user by API key
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.apiKey, apiKey as string))
      .limit(1);
    if (!user) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    const { url, source } = req.body;
    if (!url || !source) {
      return res.status(400).json({ error: "url and source are required" });
    }

    try {
      const baseLink = await getRewrittenUrl(url, user.id, source);

      // Append ssid and source parameters to the base tracking link
      const finalUrl = new URL(baseLink);
      finalUrl.searchParams.set("ssid", user.ssid);
      finalUrl.searchParams.set("source", source);

      res.json({ rewrittenUrl: finalUrl.toString() });
    } catch (err: any) {
      console.error("Rewrite error:", err);
      res.status(500).json({
        error: "Failed to rewrite link",
        message: err?.message || String(err),
      });
    }
  });

  app.get("/api/stats/:type", async (req, res) => {
    const apiKey = req.headers["x-api-key"];
    if (!apiKey) {
      return res.status(401).json({ error: "Missing X-API-KEY header" });
    }

    // Find user by API key
    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.apiKey, apiKey as string))
      .limit(1);
    if (!user) {
      return res.status(401).json({ error: "Invalid API key" });
    }

    const { type } = req.params;
    const { timeStart, timeEnd } = req.query as { [key: string]: string };
    if (!timeStart || !timeEnd) {
      return res.status(400).json({ error: "timeStart and timeEnd are required" });
    }

    try {
      const endpoint = `reports/${type}`;
      const data = await fetchStrackrStats(endpoint, {
        time_start: timeStart,
        time_end: timeEnd,
        time_type: "checked",
        ssid: user.ssid,
      });
      res.json(data);
    } catch (err: any) {
      console.error(`Stats error for ${type}:`, err);
      res.status(500).json({
        error: `Failed to fetch ${type} stats`,
        message: err?.message || String(err),
      });
    }
  });

  // Protected dashboard endpoints 
  app.get("/api/links", authenticateRequest, async (req, res) => {
    try {
      if (!req.user?.id) {
        return res.status(401).json({ error: "No user found in session" });
      }
      const userLinks = await db
        .select()
        .from(links)
        .where(eq(links.userId, req.user.id))
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
