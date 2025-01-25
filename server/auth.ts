import { type Express, Request, Response, NextFunction } from "express";
import session from "express-session";
import createMemoryStore from "memorystore";
import passport from "passport";
import { IVerifyOptions, Strategy as LocalStrategy } from "passport-local";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import { users, insertUserSchema, type SelectUser } from "@db/schema";
import { db } from "@db";
import { eq } from "drizzle-orm";
import rateLimit from 'express-rate-limit';

const scryptAsync = promisify(scrypt);

// For demonstration only. We keep a set of OAuth tokens in memory.
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "affiliate-link-manager-client";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || randomBytes(32).toString("hex");
const OAUTH_SCOPES = ["rewrite"];
const tokenStore = new Map<
  string, // token
  {
    accessToken: string;
    userId: number;
    expiresAt: number;
  }
>();

// Minimal crypto helpers for password hashing
const crypto = {
  hash: async (password: string) => {
    const salt = randomBytes(16).toString("hex");
    const buf = (await scryptAsync(password, salt, 64)) as Buffer;
    return `${buf.toString("hex")}.${salt}`;
  },
  compare: async (suppliedPassword: string, storedPassword: string) => {
    const [hashedPassword, salt] = storedPassword.split(".");
    const hashedPasswordBuf = Buffer.from(hashedPassword, "hex");
    const suppliedPasswordBuf = (await scryptAsync(suppliedPassword, salt, 64)) as Buffer;
    return timingSafeEqual(hashedPasswordBuf, suppliedPasswordBuf);
  },
};

declare global {
  namespace Express {
    interface User extends SelectUser {}
    interface Request {
      oauthToken?: { userId: number };
    }
  }
}

/**
 * Middleware that checks for a Bearer token in the Authorization header.
 * If present (and valid), we store `req.oauthToken = { userId }`.
 */
export function verifyOAuthToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return next();
  }
  const token = authHeader.slice(7);
  const tokenData = tokenStore.get(token);
  if (!tokenData || tokenData.expiresAt < Date.now()) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
  req.oauthToken = { userId: tokenData.userId };
  next();
}

/**
 * This is used by routes that *should* require an authenticated user (session or token).
 * For GPT usage, we simply do NOT call this in /api/rewrite or /api/stats, so it
 * never forces a login redirect.
 */
export function authenticateRequest(req: Request, res: Response, next: NextFunction) {
  if (req.isAuthenticated() || req.oauthToken) {
    return next();
  }
  return res.status(401).json({ error: "Authentication required" });
}

export function setupAuth(app: Express) {
  // Rate limiting for auth endpoints
  app.set("trust proxy", 1);
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: { error: "Too many requests, please try again later." },
  });

  // Basic session setup
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
    sessionSettings.cookie = { secure: true };
  }

  app.use(session(sessionSettings));
  app.use(passport.initialize());
  app.use(passport.session());
  // If we find a Bearer token, we parse it into req.oauthToken:
  app.use(verifyOAuthToken);

  /**
   * ---------------------------------------------------------------------
   * PASSPORT LOCAL STRATEGY
   * ---------------------------------------------------------------------
   */
  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const [user] = await db
          .select()
          .from(users)
          .where(eq(users.username, username))
          .limit(1);
        if (!user) {
          return done(null, false, { message: "Incorrect username." } as IVerifyOptions);
        }
        const isMatch = await crypto.compare(password, user.password);
        if (!isMatch) {
          return done(null, false, { message: "Incorrect password." } as IVerifyOptions);
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    })
  );

  passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  passport.deserializeUser(async (id: number, done) => {
    try {
      const [user] = await db.select().from(users).where(eq(users.id, id)).limit(1);
      done(null, user);
    } catch (err) {
      done(err);
    }
  });

  /**
   * ---------------------------------------------------------------------
   * OPTIONAL: OAuth-like endpoints for bot access or service accounts
   * ---------------------------------------------------------------------
   */
  app.post("/api/auth", authLimiter, async (req, res) => {
    const { client_id, client_secret } = req.body;
    if (client_id !== OAUTH_CLIENT_ID || client_secret !== OAUTH_CLIENT_SECRET) {
      return res.status(401).json({ error: "Invalid client credentials" });
    }
    // For demonstration, we create a short-lived "Bearer token" for userId=1
    const accessToken = randomBytes(32).toString("hex");
    tokenStore.set(accessToken, {
      accessToken,
      userId: 1,
      expiresAt: Date.now() + 60 * 60 * 1000, // 1 hour
    });
    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: OAUTH_SCOPES.join(" "),
    });
  });

  app.post("/api/token", authLimiter, async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Basic ")) {
      return res.status(401).json({ error: "Missing or invalid auth header" });
    }
    const [clientId, clientSecret] = Buffer.from(
      authHeader.slice(6),
      "base64"
    )
      .toString()
      .split(":");

    if (clientId !== OAUTH_CLIENT_ID || clientSecret !== OAUTH_CLIENT_SECRET) {
      return res.status(401).json({ error: "Invalid client credentials" });
    }

    const { grant_type, refresh_token } = req.body;
    if (grant_type !== "refresh_token" || !refresh_token) {
      return res
        .status(400)
        .json({ error: "Missing or invalid grant_type/refresh_token" });
    }
    // In a real system, you'd verify refresh_token. For now, we just re-issue a token.
    const accessToken = randomBytes(32).toString("hex");
    tokenStore.set(accessToken, {
      accessToken,
      userId: 1,
      expiresAt: Date.now() + 60 * 60 * 1000,
    });
    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      scope: OAUTH_SCOPES.join(" "),
    });
  });

  app.get("/api/oauth-credentials", (req, res) => {
    res.json({
      client_id: OAUTH_CLIENT_ID,
      client_secret: OAUTH_CLIENT_SECRET,
      authorization_url: `${req.protocol}://${req.get("host")}/api/auth`,
      token_url: `${req.protocol}://${req.get("host")}/api/token`,
      scopes: OAUTH_SCOPES,
    });
  });

  /**
   * ---------------------------------------------------------------------
   * REGISTER + LOGIN + LOGOUT + GET USER
   * ---------------------------------------------------------------------
   * You can keep these as-is for your user dashboard logic.
   */
  app.post("/api/register", async (req, res, next) => {
    try {
      const result = insertUserSchema.safeParse(req.body);
      if (!result.success) {
        const errors = result.error.issues.map((i) => i.message).join(", ");
        return res.status(400).send("Invalid input: " + errors);
      }
      const { username, password } = result.data;
      // Check for existing
      const [existing] = await db
        .select()
        .from(users)
        .where(eq(users.username, username))
        .limit(1);
      if (existing) {
        return res.status(400).send("Username already exists");
      }
      const hashedPassword = await crypto.hash(password);
      const [newUser] = await db
        .insert(users)
        .values({
          username,
          password: hashedPassword,
        })
        .returning();
      req.login(newUser, (err) => {
        if (err) return next(err);
        res.json({
          message: "Registration successful",
          user: {
            id: newUser.id,
            username: newUser.username,
            ssid: newUser.ssid,
            createdAt: newUser.createdAt,
          },
        });
      });
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/login", (req, res, next) => {
    passport.authenticate("local", (err: any, user: Express.User, info: IVerifyOptions) => {
      if (err) return next(err);
      if (!user) {
        return res.status(400).send(info?.message ?? "Login failed");
      }
      req.logIn(user, (err) => {
        if (err) return next(err);
        res.json({
          message: "Login successful",
          user: {
            id: user.id,
            username: user.username,
            ssid: user.ssid,
            createdAt: user.createdAt,
          },
        });
      });
    })(req, res, next);
  });

  app.post("/api/logout", (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(200).json({ message: "Already logged out" });
    }
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ error: "Logout failed", message: err.message });
      }
      req.session.destroy((sessErr) => {
        if (sessErr) {
          return res
            .status(500)
            .json({ error: "Session destruction failed", message: sessErr.message });
        }
        res.json({ message: "Logout successful" });
      });
    });
  });

  app.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    res.json({
      id: req.user!.id,
      username: req.user!.username,
      ssid: req.user!.ssid,
      createdAt: req.user!.createdAt,
    });
  });
}
