import type { Express } from "express";
import { createServer, type Server } from "http";
import axios from "axios";
import { db } from "@db";
import { links, users } from "@db/schema";
import { eq } from "drizzle-orm";
import { setupAuth, authenticateRequest } from "./auth";
import { createClient } from 'redis';

// Redis client setup for production caching
const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379',
  socket: {
    reconnectStrategy: (retries) => {
      // Exponential backoff with max delay of 10 seconds
      const delay = Math.min(Math.pow(2, retries) * 100, 10000);
      console.log(`Redis reconnecting in ${delay}ms... (attempt ${retries + 1})`);
      return delay;
    },
    connectTimeout: 10000, // 10 seconds
    keepAlive: 1000, // Send keepalive packet every 1000ms
    noDelay: true, // Disable Nagle's algorithm
    tls: process.env.REDIS_URL?.startsWith('rediss://') ? {} : undefined
  }
});

// Connect to Redis and handle connection errors
redisClient.connect().catch(err => {
  console.error('Redis connection error:', err);
  if (process.env.REDIS_URL) {
    console.log('Redis URL format (for debugging):', process.env.REDIS_URL.replace(/\/\/.*@/, '//<credentials>@'));
  } else {
    console.log('No REDIS_URL provided, falling back to localhost');
  }
});

redisClient.on('error', err => {
  console.error('Redis error:', err);
});

redisClient.on('connect', () => {
  console.log('Successfully connected to Redis');
});

redisClient.on('reconnecting', () => {
  console.log('Redis reconnecting...');
});

redisClient.on('ready', () => {
  console.log('Redis client is ready');
});

const CACHE_TTL = 3600; // 1 hour in seconds

/**
 * getRewrittenUrl:
 * 1. Checks Redis cache for existing rewritten URL
 * 2. If not found, calls Strackr's link builder endpoint
 * 3. Caches successful responses in Redis for future use
 * 4. Includes fallback behavior if Redis is unavailable
 */
async function getRewrittenUrl(
  originalUrl: string,
  userId: number,
  source: string
): Promise<string> {
  const cacheKey = `url:${userId}:${originalUrl}:${source}`;

  try {
    // Check if Redis is connected before attempting operations
    if (!redisClient.isOpen) {
      console.warn('Redis not connected - bypassing cache');
    } else {
      // Try to get from Redis cache first
      const cachedUrl = await redisClient.get(cacheKey);
      if (cachedUrl) {
        console.log('Cache hit for:', cacheKey);
        return cachedUrl;
      }
      console.log('Cache miss for:', cacheKey);
    }
  } catch (cacheError) {
    // Log Redis errors but continue with API call
    console.error('Redis cache error:', cacheError);
  }

  // Not in cache or Redis error => call Strackr
  try {
    console.log('Fetching from Strackr API for:', originalUrl);
    const resp = await axios.get("https://api.strackr.com/v3/tools/linkbuilder", {
      params: {
        api_id: process.env.STRACKR_API_ID,
        api_key: process.env.STRACKR_API_KEY,
        url: originalUrl,
      },
      headers: {
        "User-Agent": "MonetizeChatbots/1.0",
      },
    });
    const data = resp.data;

    // Validate API response structure
    if (
      !data.results ||
      !Array.isArray(data.results) ||
      data.results.length === 0 ||
      !data.results[0].advertisers ||
      data.results[0].advertisers.length === 0 ||
      !data.results[0].advertisers[0].connections ||
      data.results[0].advertisers[0].connections.length === 0 ||
      !data.results[0].advertisers[0].connections[0].links ||
      data.results[0].advertisers[0].connections[0].links.length === 0
    ) {
      console.error("Strackr API response:", JSON.stringify(data, null, 2));
      throw new Error("No valid tracking link found from Strackr – full response: " + JSON.stringify(data));
    }

    const trackingLink = data.results[0].advertisers[0].connections[0].links[0].trackinglink;
    if (!trackingLink) {
      throw new Error("Tracking link is empty or undefined");
    }

    try {
      if (redisClient.isOpen) {
        // Store in Redis cache with TTL
        await redisClient.setEx(cacheKey, CACHE_TTL, trackingLink);
        console.log('Cached new tracking link for:', cacheKey);
      }
    } catch (cacheError) {
      // Log Redis errors but don't fail the request
      console.error('Redis cache set error:', cacheError);
    }

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