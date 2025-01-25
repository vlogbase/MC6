import { type Express, Request, Response, NextFunction } from "express";
import { randomBytes } from "crypto";
import { scrypt, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { users, insertUserSchema, type SelectUser } from "@db/schema";
import { db } from "@db";
import { eq } from "drizzle-orm";
import rateLimit from 'express-rate-limit';

const scryptAsync = promisify(scrypt);

// OAuth Configuration
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "affiliate-link-manager-client";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || randomBytes(32).toString('hex');
const OAUTH_SCOPES = ["rewrite"];

// Store OAuth tokens
const tokenStore = new Map<string, {
  accessToken: string,
  expiresAt: number,
  scope: string[]
}>();

const crypto = {
  hash: async (password: string) => {
    const salt = randomBytes(16).toString("hex");
    const buf = (await scryptAsync(password, salt, 64)) as Buffer;
    return `${buf.toString("hex")}.${salt}`;
  },
  compare: async (suppliedPassword: string, storedPassword: string) => {
    const [hashedPassword, salt] = storedPassword.split(".");
    const hashedPasswordBuf = Buffer.from(hashedPassword, "hex");
    const suppliedPasswordBuf = (await scryptAsync(
      suppliedPassword,
      salt,
      64
    )) as Buffer;
    return timingSafeEqual(hashedPasswordBuf, suppliedPasswordBuf);
  },
};

declare global {
  namespace Express {
    interface User extends SelectUser {}
  }
}

export function verifyOAuthToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: "Bearer token required" });
  }

  const token = authHeader.slice(7);
  const tokenData = tokenStore.get(token);

  if (!tokenData || tokenData.expiresAt < Date.now()) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }

  next();
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

  // OAuth endpoints
  app.post("/api/auth", authLimiter, async (req, res) => {
    const { client_id, client_secret } = req.body;

    if (client_id !== OAUTH_CLIENT_ID || client_secret !== OAUTH_CLIENT_SECRET) {
      return res.status(401).json({ error: "Invalid client credentials" });
    }

    const accessToken = randomBytes(32).toString('hex');
    tokenStore.set(accessToken, {
      accessToken,
      expiresAt: Date.now() + (60 * 60 * 1000), // 1 hour expiry
      scope: OAUTH_SCOPES
    });

    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: OAUTH_SCOPES.join(" ")
    });
  });


  // Export OAuth credentials for frontend use
  app.get("/api/oauth-credentials", (req, res) => {
    res.json({
      client_id: OAUTH_CLIENT_ID,
      client_secret: OAUTH_CLIENT_SECRET,
      authorization_url: `${req.protocol}://${req.get('host')}/api/auth`,
      token_url: `${req.protocol}://${req.get('host')}/api/token`,
      scopes: OAUTH_SCOPES,
      token_exchange_method: "post"
    });
  });

  app.post("/api/register", async (req, res, next) => {
    try {
      const result = insertUserSchema.safeParse(req.body);
      if (!result.success) {
        return res
          .status(400)
          .send("Invalid input: " + result.error.issues.map(i => i.message).join(", "));
      }

      const { username, password } = result.data;

      // Check if user already exists
      const [existingUser] = await db
        .select()
        .from(users)
        .where(eq(users.username, username))
        .limit(1);

      if (existingUser) {
        return res.status(400).send("Username already exists");
      }

      // Hash the password
      const hashedPassword = await crypto.hash(password);

      // Create the new user with SSID
      const [newUser] = await db
        .insert(users)
        .values({
          username,
          password: hashedPassword,
        })
        .returning();

      res.json({
        message: "Registration successful",
        user: {
          id: newUser.id,
          username: newUser.username,
          createdAt: newUser.createdAt
        },
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/login", async (req, res, next) => {
    try {
      const { username, password } = req.body;

      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.username, username))
        .limit(1);

      if (!user) {
        return res.status(400).send("Incorrect username.");
      }

      const isMatch = await crypto.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).send("Incorrect password.");
      }

      res.json({
        message: "Login successful",
        user: {
          id: user.id,
          username: user.username,
          createdAt: user.createdAt
        },
      });

    } catch (err) {
      next(err);
    }
  });

  app.post("/api/logout", (req, res) => {
    res.json({ message: "Logout successful" }); //Simplified logout - no session to destroy
  });

  app.get("/api/user", async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: "Bearer token required" });
    }

    const token = authHeader.slice(7);
    const tokenData = tokenStore.get(token);

    if (!tokenData || tokenData.expiresAt < Date.now()) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    
    //Assuming user data can be retrieved based on tokenData.  This is a placeholder and needs actual implementation.
    res.json({
      // ... user data based on tokenData
    });

  });
}

export function ensureAuthenticated(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return next();
  }
  return res.status(401).json({ error: "Authentication required" });
}