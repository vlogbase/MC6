import type { Express } from "express";
import { createServer, type Server } from "http";
import { verifyOAuthToken } from "./auth";
import axios from "axios";
import { db } from "@db";
import { links } from "@db/schema";
import { eq } from "drizzle-orm";

// Simple in-memory cache
const urlCache = new Map<string, {
  rewrittenUrl: string;
  timestamp: number;
}>();

const CACHE_TTL = 3600000; // 1 hour in milliseconds

async function getRewrittenUrl(originalUrl: string, source: string) {
  // Generate cache key
  const cacheKey = `${originalUrl}:${source}`;

  // Check cache first
  const cached = urlCache.get(cacheKey);
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
    return cached.rewrittenUrl;
  }

  // If not in cache or expired, call Strackr API
  try {
    const response = await axios.get(
      "https://api.strackr.com/v3/tools/linkbuilder",
      {
        params: {
          api_id: process.env.STRACKR_API_ID,
          api_key: process.env.STRACKR_API_KEY,
          url: originalUrl
        },
      }
    );

    // Parse the response to find a tracking link
    const data = response.data;
    let trackingLink;
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

    // Store in cache
    urlCache.set(cacheKey, {
      rewrittenUrl: trackingLink,
      timestamp: Date.now()
    });

    // Store in database
    await db.insert(links).values({
      originalUrl,
      rewrittenUrl: trackingLink,
      source
    });

    return trackingLink;
  } catch (error: any) {
    console.error("Strackr API error:", error.message);
    throw error;
  }
}

async function fetchStrackrStats(endpoint: string, params: Record<string, string>) {
  try {
    const response = await axios.get(`https://api.strackr.com/v3/${endpoint}`, {
      params: {
        api_id: process.env.STRACKR_API_ID,
        api_key: process.env.STRACKR_API_KEY,
        ...params
      }
    });
    return response.data;
  } catch (error: any) {
    console.error(`Strackr ${endpoint} error:`, error.message);
    throw error;
  }
}

export function registerRoutes(app: Express): Server {
  // Rewrite URL endpoint
  app.post("/api/rewrite", verifyOAuthToken, async (req, res) => {
    try {
      const { url, source } = req.body;

      if (!url || !source) {
        return res.status(400).json({ error: "URL and source are required" });
      }

      const rewrittenUrl = await getRewrittenUrl(url, source);
      res.json({ rewrittenUrl });
    } catch (error: any) {
      console.error("Rewrite error:", error);
      res.status(500).json({ 
        error: "Failed to rewrite URL",
        message: error.message 
      });
    }
  });

  // Strackr Stats endpoints
  app.get("/api/stats/:type", verifyOAuthToken, async (req, res) => {
    try {
      const { type } = req.params;
      const { timeStart, timeEnd } = req.query;

      if (!timeStart || !timeEnd) {
        return res.status(400).json({ error: "Time range is required" });
      }

      const endpoint = `reports/${type}`;
      const data = await fetchStrackrStats(endpoint, {
        time_start: timeStart as string,
        time_end: timeEnd as string,
        time_type: 'checked'
      });

      res.json(data);
    } catch (error: any) {
      console.error(`Stats error for ${req.params.type}:`, error);
      res.status(500).json({ 
        error: `Failed to fetch ${req.params.type} stats`,
        message: error.message 
      });
    }
  });

  // Get user's links
  app.get("/api/links", verifyOAuthToken, async (req, res) => {
    try {
      const userLinks = await db
        .select()
        .from(links)
        .orderBy(links.createdAt);

      res.json(userLinks);
    } catch (error: any) {
      console.error("Error fetching links:", error);
      res.status(500).json({ 
        error: "Failed to fetch links",
        message: error.message 
      });
    }
  });

  // Create and return HTTP server
  const httpServer = createServer(app);
  return httpServer;
}