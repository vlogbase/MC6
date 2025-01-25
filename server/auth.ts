import { type Express, Request, Response, NextFunction } from "express";
import session from "express-session";
import createMemoryStore from "memorystore";
import passport from "passport";
import { randomBytes } from "crypto";
import rateLimit from 'express-rate-limit';

// OAuth Configuration
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "affiliate-link-manager-client";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || randomBytes(32).toString('hex');
const OAUTH_SCOPES = ["rewrite"];

// Store OAuth tokens
const tokenStore = new Map<string, {
  accessToken: string,
  expiresAt: number
}>();

declare global {
  namespace Express {
    interface Request {
      oauthToken?: { accessToken: string };
    }
  }
}

export function verifyOAuthToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return next();
  }

  const token = authHeader.slice(7);
  const tokenData = tokenStore.get(token);

  if (!tokenData || tokenData.expiresAt < Date.now()) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  req.oauthToken = { accessToken: token };
  next();
}

export function authenticateRequest(req: Request, res: Response, next: NextFunction) {
  if (req.oauthToken) {
    return next();
  }
  res.status(401).json({ error: "Authentication required" });
}

export function setupAuth(app: Express) {
  // Trust proxy for rate limiter
  app.set('trust proxy', 1);

  // Rate limiting for auth endpoints
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later.' }
  });

  const MemoryStore = createMemoryStore(session);
  const sessionSettings: session.SessionOptions = {
    secret: process.env.REPL_ID || "porygon-supremacy",
    resave: false,
    saveUninitialized: false,
    cookie: {},
    store: new MemoryStore({
      checkPeriod: 86400000, // prune expired entries every 24h
    }),
  };

  if (app.get("env") === "production") {
    sessionSettings.cookie = {
      secure: true,
    };
  }

  app.use(session(sessionSettings));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(verifyOAuthToken);

  // Simplified OAuth token endpoint
  app.post("/api/auth", authLimiter, async (req, res) => {
    const { client_id, client_secret } = req.body;

    if (client_id !== OAUTH_CLIENT_ID || client_secret !== OAUTH_CLIENT_SECRET) {
      return res.status(401).json({ error: "Invalid client credentials" });
    }

    const accessToken = randomBytes(32).toString('hex');
    tokenStore.set(accessToken, {
      accessToken,
      expiresAt: Date.now() + (60 * 60 * 1000) // 1 hour expiry
    });

    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: OAUTH_SCOPES.join(" ")
    });
  });

  // OAuth credentials endpoint
  app.get("/api/oauth-credentials", (req, res) => {
    res.json({
      client_id: OAUTH_CLIENT_ID,
      client_secret: OAUTH_CLIENT_SECRET,
      token_url: `${req.protocol}://${req.get('host')}/api/auth`,
      scopes: OAUTH_SCOPES,
      token_exchange_method: "post"
    });
  });
}