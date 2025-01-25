import type { Express } from "express";
import { createServer, type Server } from "http";
import axios from "axios";
import { db } from "@db";
import { links } from "@db/schema";
import { eq } from "drizzle-orm";
import { setupAuth } from "./auth";
import { authenticateRequest } from "./auth";

/**
 * ----------------------------------------------------------------------------
 * SIMPLE IN-MEMORY CACHE for Link Rewrites
 * ----------------------------------------------------------------------------
 * We store (userId, originalUrl, source) => { rewrittenUrl, timestamp }
 * to avoid repeatedly calling Strackr for the same link.
 */
const urlCache = new Map<
  string, // e.g. `${userId}:${originalUrl}:${source}`
  {
    rewrittenUrl: string;
    timestamp: number;
  }
>();
const CACHE_TTL = 3600000; // 1 hour in milliseconds

/**
 * This function calls Strackr's /tools/linkbuilder only when NOT cached.
 * (And we store new links to the DB under a "system" user or real user.)
 */
async function getRewrittenUrl(
  originalUrl: string,
  userId: number,
  source: string
): Promise<string> {
  // Make a unique cache key
  const cacheKey = `${userId}:${originalUrl}:${source}`;

  // 1. Check our in-memory cache first
  const cached = urlCache.get(cacheKey);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.rewrittenUrl;
  }

  // 2. Otherwise, call Strackr
  try {
    const response = await axios.get("https://api.strackr.com/v3/tools/linkbuilder", {
      params: {
        api_id: process.env.STRACKR_API_ID,
        api_key: process.env.STRACKR_API_KEY,
        url: originalUrl,
      },
    });

    // 3. Pick the first tracking link from Strackr’s response
    const data = response.data;
    let trackingLink: string | undefined;
    const [first] = data.results || [];
    if (first?.advertisers?.length > 0) {
      const adv = first.advertisers[0];
      if (adv.connections?.length > 0) {
        const conn = adv.connections[0];
        if (conn.links?.length > 0) {
          trackingLink = conn.links[0].trackinglink;
        }
      }
    }

    if (!trackingLink) {
      throw new Error("No tracking link found from Strackr");
    }

    // 4. Cache it in memory
    urlCache.set(cacheKey, {
      rewrittenUrl: trackingLink,
      timestamp: Date.now(),
    });

    // 5. Also store in the DB (optional). If you want the user-based approach,
    //    pass a real userId. If you want "system" storage for GPT, pick userId=1.
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

/**
 * ----------------------------------------------------------------------------
 * GET STRACKR STATS (optional, if you want to fetch stats similarly)
 * ----------------------------------------------------------------------------
 */
async function fetchStrackrStats(
  endpoint: string,
  params: Record<string, string>
): Promise<any> {
  try {
    const response = await axios.get(`https://api.strackr.com/v3/${endpoint}`, {
      params: {
        api_id: process.env.STRACKR_API_ID,
        api_key: process.env.STRACKR_API_KEY,
        ...params,
      },
    });
    return response.data;
  } catch (error: any) {
    console.error(`Strackr ${endpoint} error:`, error?.message || error);
    throw error;
  }
}

export function registerRoutes(app: Express): Server {
  // Sets up session-based auth (local strategy, OAuth). See auth.ts below
  setupAuth(app);

  /**
   * ---------------------------------------------------------
   * /api/rewrite - NO LOGIN REQUIRED
   * ---------------------------------------------------------
   * GPT or any system can POST { url, source } here. We do:
   *  1. Check local cache
   *  2. If missing, call Strackr
   *  3. Store in DB under userId=1 (or any ID you want)
   */
  app.post("/api/rewrite", async (req, res) => {
    try {
      const { url, source } = req.body;
      if (!url || !source) {
        return res
          .status(400)
          .json({ error: "Both 'url' and 'source' are required." });
      }
      // If you want them stored under a "system" user, pick userId=1:
      const systemUserId = 1;
      const rewrittenUrl = await getRewrittenUrl(url, systemUserId, source);
      return res.json({ rewrittenUrl });
    } catch (error: any) {
      console.error("Rewrite error:", error);
      return res.status(500).json({
        error: "Failed to rewrite link",
        message: error?.message || String(error),
      });
    }
  });

  /**
   * ---------------------------------------------------------
   * /api/stats/:type - NO LOGIN REQUIRED
   * ---------------------------------------------------------
   * For GPT usage, your AI can call /api/stats/clicks or /api/stats/transactions
   * or whatever. We skip session-check so it never asks for login.
   * Query params: ?timeStart=YYYY-MM-DD&timeEnd=YYYY-MM-DD
   */
  app.get("/api/stats/:type", async (req, res) => {
    try {
      const { type } = req.params;
      const { timeStart, timeEnd } = req.query;
      if (!timeStart || !timeEnd) {
        return res
          .status(400)
          .json({ error: "Must provide 'timeStart' and 'timeEnd' query params" });
      }
      // e.g. endpoint = 'reports/clicks' or 'reports/transactions'
      // If your "type" is something else, adjust this logic as needed
      const endpoint = `reports/${type}`;

      const data = await fetchStrackrStats(endpoint, {
        time_start: String(timeStart),
        time_end: String(timeEnd),
        time_type: "checked",
      });
      return res.json(data);
    } catch (error: any) {
      console.error(`Stats error for ${req.params.type}:`, error);
      return res.status(500).json({
        error: `Failed to fetch ${req.params.type} stats`,
        message: error?.message || String(error),
      });
    }
  });

  /**
   * ---------------------------------------------------------
   * PROTECTED ROUTES (REMAINING)
   * ---------------------------------------------------------
   * e.g. retrieving a user’s own links. We'll keep these behind
   * authenticateRequest so your normal user dashboard requires login.
   */
  app.get("/api/links", authenticateRequest, async (req, res) => {
    try {
      const userId = req.user?.id || req.oauthToken?.userId;
      if (!userId) {
        return res.status(401).json({ error: "Not authenticated" });
      }
      const userLinks = await db
        .select()
        .from(links)
        .where(eq(links.userId, userId))
        .orderBy(links.createdAt);
      return res.json(userLinks);
    } catch (error
