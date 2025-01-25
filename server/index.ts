import express, { type Express, Request, Response, NextFunction } from "express";
import rateLimit from "express-rate-limit";
import { randomBytes } from "crypto";
import { createServer } from "http";
import { setupAuth, authenticateRequest } from "./auth";

const app = express();
const PORT = process.env.PORT || 3000;

// In-memory store of { token -> { accessToken, userId, expiresAt } }
const tokenStore = new Map<
  string,
  {
    accessToken: string;
    userId: number;
    expiresAt: number;
  }
>();

// For demonstration, we hardcode userId=1 for all tokens, or you can adapt it:
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "affiliate-link-manager-client";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || randomBytes(32).toString("hex");
const OAUTH_SCOPES = ["rewrite"];

// Extend Express so we can store the user's ID if a valid token is found
declare global {
  namespace Express {
    interface Request {
      oauthToken?: { userId: number };
    }
  }
}

// Middleware to verify a "Bearer <token>" in the Authorization header
export function verifyOAuthToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return next(); // No token in header; we simply proceed so we can handle public endpoints
  }

  const token = authHeader.slice(7);
  const tokenData = tokenStore.get(token);

  // Token missing or expired?
  if (!tokenData || tokenData.expiresAt < Date.now()) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  // Attach user info to request, so routes can see userId
  req.oauthToken = { userId: tokenData.userId };
  next();
}

// Middleware that *requires* a valid OAuth token
export function authenticateRequest(req: Request, res: Response, next: NextFunction) {
  if (req.oauthToken) {
    return next();
  }
  return res.status(401).json({ error: "Authentication required" });
}

export function setupAuth(app: Express) {
  // Simple rate limiter for auth endpoints
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: { error: "Too many requests, please try again later." },
  });

  // Attach `verifyOAuthToken` globally so all requests parse potential Bearer tokens
  app.use(verifyOAuthToken);

  // 1) Client Credentials: exchange client_id + client_secret for a token
  app.post("/api/auth", authLimiter, (req, res) => {
    const { client_id, client_secret } = req.body;
    if (client_id !== OAUTH_CLIENT_ID || client_secret !== OAUTH_CLIENT_SECRET) {
      return res.status(401).json({ error: "Invalid client credentials" });
    }

    // Generate an access token. For simplicity, we fix userId=1. Adjust as needed.
    const accessToken = randomBytes(32).toString("hex");
    tokenStore.set(accessToken, {
      accessToken,
      userId: 1,
      expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour from now
    });

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: OAUTH_SCOPES.join(" "),
    });
  });

  // 2) (Optional) Refresh route if you want to allow "refresh_token" flows using Basic auth
  app.post("/api/token", authLimiter, (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Basic ")) {
      return res.status(401).json({ error: "Missing authorization header" });
    }
    const base64 = authHeader.slice(6);
    const decoded = Buffer.from(base64, "base64").toString();
    const [clientId, clientSecret] = decoded.split(":");
    if (clientId !== OAUTH_CLIENT_ID || clientSecret !== OAUTH_CLIENT_SECRET) {
      return res.status(401).json({ error: "Invalid client credentials" });
    }

    const { grant_type } = req.body;
    if (grant_type !== "refresh_token") {
      return res.status(400).json({ error: "Invalid grant_type" });
    }

    // Issue a new access token
    const accessToken = randomBytes(32).toString("hex");
    tokenStore.set(accessToken, {
      accessToken,
      userId: 1, // In a real app, you'd identify which user is being refreshed
      expiresAt: Date.now() + 60 * 60 * 1000,
    });

    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: OAUTH_SCOPES.join(" "),
    });
  });

  // 3) Expose the OAuth credentials for the front end to read/copy
  app.get("/api/oauth-credentials", (req, res) => {
    res.json({
      client_id: OAUTH_CLIENT_ID,
      client_secret: OAUTH_CLIENT_SECRET,
      authorization_url: `${req.protocol}://${req.get("host")}/api/auth`,
      token_url: `${req.protocol}://${req.get("host")}/api/token`,
      scopes: OAUTH_SCOPES,
      token_exchange_method: "basic_auth",
    });
  });
}


const httpServer = createServer(app);
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
export default httpServer;