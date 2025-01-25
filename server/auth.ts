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
import rateLimit from "express-rate-limit";

const scryptAsync = promisify(scrypt);

/**
 * Configure these from environment or defaults:
 * We want GPT to do a client_credentials flow, so we must have:
 *  1) OAUTH_CLIENT_ID
 *  2) OAUTH_CLIENT_SECRET
 */
const OAUTH_CLIENT_ID =
  process.env.OAUTH_CLIENT_ID || "my-client-id-from-env";
const OAUTH_CLIENT_SECRET =
  process.env.OAUTH_CLIENT_SECRET || randomBytes(32).toString("hex");
const OAUTH_SCOPES = ["rewrite"];

/**
 * In-memory store of valid tokens. Key = token string, value includes
 * userId, expiresAt, etc. This is how we "verify" the Bearer token later.
 */
type TokenData = {
  accessToken: string;
  userId: number;
  expiresAt: number; // ms epoch
};
const tokenStore = new Map<string, TokenData>();

/**
 * Minimal crypto helpers for local user password hashing
 * (unrelated to GPT usage, but we keep them for your existing user login)
 */
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
 * verifyOAuthToken
 * Middleware that checks for "Authorization: Bearer ..."
 *  - If found, we see if it's in tokenStore and not expired.
 *  - If valid, we set req.oauthToken = { userId: ... }
 *  - Otherwise, do 401 or next().
 */
export function verifyOAuthToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return next(); // no Bearer token found
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
 * authenticateRequest
 * If a route calls this, it means "user must be logged in or have a valid Bearer token."
 */
export function authenticateRequest(req: Request, res: Response, next: NextFunction) {
  // If there's a session-based user (req.isAuthenticated()) or an OAuth token, pass
  if (req.isAuthenticated() || req.oauthToken) {
    return next();
  }
  return res.status(401).json({ error: "Authentication required" });
}

export function setupAuth(app: Express) {
  // Rate limiting for login- or token- related endpoints
  app.set("trust proxy", 1);
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: { error: "Too many requests, please try again later." },
  });

  // Basic session setup for your local strategy
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
  // ALWAYS parse Bearer token if present:
  app.use(verifyOAuthToken);

  /**
   * -------------------------------------------------------------------
   * PASSPORT LOCAL STRATEGY (for your user dashboard, ignoring GPT use)
   * -------------------------------------------------------------------
   */
  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const [user] = await db.select().from(users).where(eq(users.username, username)).limit(1);
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
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  });

  /**
   * -------------------------------------------------------------------
   * CLIENT CREDENTIALS FLOW:
   * "POST /api/token" with Basic Auth + grant_type=client_credentials
   * No login screen. We return a Bearer token in JSON.
   * -------------------------------------------------------------------
   */
  app.post("/api/token", authLimiter, async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Basic ")) {
      return res.status(401).json({ error: "Missing or invalid Authorization header" });
    }

    // Typically "Authorization: Basic base64(clientId:clientSecret)"
    const base64 = authHeader.slice(6);
    const [clientId, clientSecret] = Buffer.from(base64, "base64").toString().split(":");

    if (clientId !== OAUTH_CLIENT_ID || clientSecret !== OAUTH_CLIENT_SECRET) {
      return res.status(401).json({ error: "Invalid client credentials" });
    }

    const { grant_type } = req.body;
    if (grant_type !== "client_credentials") {
      return res.status(400).json({ error: "grant_type must be client_credentials" });
    }

    // Now we accept. We'll create a random token, store it in memory, expires in 1 hour
    const accessToken = randomBytes(32).toString("hex");
    const expiresIn = 3600; // seconds
    tokenStore.set(accessToken, {
      accessToken,
      userId: 1, // Hard-coded system user or whatever numeric ID
      expiresAt: Date.now() + expiresIn * 1000,
    });

    // Return standard OAuth2.0 response
    res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: expiresIn,
      scope: OAUTH_SCOPES.join(" "),
    });
  });

  // Optional: A route to show credentials or other info
  // (You might remove it if not needed.)
  app.get("/api/oauth-credentials", (req, res) => {
    res.json({
      client_id: OAUTH_CLIENT_ID,
      client_secret: OAUTH_CLIENT_SECRET,
      token_endpoint: `${req.protocol}://${req.get("host")}/api/token`,
      scopes: OAUTH_SCOPES,
    });
  });

  /**
   * -------------------------------------------------------------------
   * REGISTER + LOGIN + LOGOUT + GET USER
   * (Your existing user-based local auth flow, for the dashboard.)
   * -------------------------------------------------------------------
   */
  app.post("/api/register", async (req, res, next) => {
    try {
      const result = insertUserSchema.safeParse(req.body);
      if (!result.success) {
        return res.status(400).send(
          "Invalid input: " +
            result.error.issues.map((i) => i.message).join(", ")
        );
      }
      const { username, password } = result.data;
      // check if user exists
      const [existing] = await db.select().from(users).where(eq(users.username, username)).limit(1);
      if (existing) {
        return res.status(400).send("Username already exists");
      }
      // create user
      const hashedPassword = await crypto.hash(password);
      const [newUser] = await db.insert(users).values({
        username,
        password: hashedPassword,
      }).returning();

      req.login(newUser, (err) => {
        if (err) return next(err);
        res.json({
          message: "Registration successful",
          user: {
            id: newUser.id,
            username: newUser.username,
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
        return res.json({
          message: "Login successful",
          user: {
            id: user.id,
            username: user.username,
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
    return res.json({
      id: req.user!.id,
      username: req.user!.username,
      createdAt: req.user!.createdAt,
    });
  });
}