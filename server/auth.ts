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
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import admin from 'firebase-admin';

const scryptAsync = promisify(scrypt);

// JWT configuration
const JWT_SECRET = process.env.JWT_SECRET || process.env.REPL_ID || "porygon-supremacy";
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || JWT_SECRET + "-refresh";
const ACCESS_TOKEN_EXPIRY = '15m';
const REFRESH_TOKEN_EXPIRY = '7d';

/**
 * Minimal crypto helpers for local user password hashing
 */
const crypto = {
  hash: async (password: string) => {
    const salt = randomBytes(16).toString("hex");
    const buf = (await scryptAsync(password, salt, 64)) as Buffer;
    return `${buf.toString("hex")}.${salt}`;
  },
  compare: async (suppliedPassword: string, storedPassword: string) => {
    if (!storedPassword) return false;
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
      token?: string;
    }
  }
}

// Initialize Firebase Admin
if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON environment variable is required');
}

// Initialize Firebase Admin using a service account
try {
  // Retrieve the full service account JSON from the secret
  const serviceAccountJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (!serviceAccountJson) {
    throw new Error("Missing Firebase Service Account JSON");
  }
  const serviceAccount = JSON.parse(serviceAccountJson);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
} catch (error) {
  console.error('Failed to initialize Firebase Admin:', error);
  throw error;
}

export function setupAuth(app: Express) {
  // Rate limiting for auth endpoints
  app.set("trust proxy", 1);
  const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: { error: "Too many requests, please try again later." },
  });

  // Basic session setup for dashboard access
  const MemoryStore = createMemoryStore(session);
  const sessionSettings: session.SessionOptions = {
    secret: JWT_SECRET,
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

  // Add token verification before passport middleware
  app.use(verifyToken);

  // Local strategy setup
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
        if (!user.password) {
          return done(null, false, { message: "No password set for this account." } as IVerifyOptions);
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

  // New endpoint to sync Firebase user with our database
  app.post("/api/sync-firebase-user", async (req, res) => {
    try {
      const { idToken } = req.body;

      if (!idToken) {
        return res.status(400).json({ error: "No ID token provided" });
      }

      // Verify the Firebase ID token
      const decodedToken = await admin.auth().verifyIdToken(idToken);
      const firebaseUid = decodedToken.uid;

      // Check if user exists in our database
      let [user] = await db
        .select()
        .from(users)
        .where(eq(users.firebaseUid, firebaseUid))
        .limit(1);

      if (!user) {
        // Create new user
        [user] = await db
          .insert(users)
          .values({
            username: decodedToken.email?.split('@')[0] || `user-${nanoid(6)}`,
            email: decodedToken.email,
            firebaseUid,
            ssid: nanoid(12),
            apiKey: nanoid(40),
          })
          .returning();

        console.log('Created new user:', user.username);
      }

      res.json({
        id: user.id,
        username: user.username,
        email: user.email,
        ssid: user.ssid,
        apiKey: user.apiKey,
      });
    } catch (error) {
      console.error('Error syncing Firebase user:', error);
      res.status(500).json({ error: "Failed to sync user" });
    }
  });

  app.post("/api/login", (req, res, next) => {
    passport.authenticate("local", (err: any, user: Express.User, info: IVerifyOptions) => {
      if (err) {
        console.error("Login error:", err);
        return next(err);
      }
      if (!user) {
        console.log("Login failed:", info?.message);
        return res.status(400).json({ error: info?.message ?? "Login failed" });
      }
      req.logIn(user, (err) => {
        if (err) {
          console.error("Session setup error:", err);
          return next(err);
        }

        console.log("Login successful for user:", user.username);
        return res.json({
          message: "Login successful",
          user: {
            id: user.id,
            username: user.username,
            ssid: user.ssid,
            apiKey: user.apiKey,
            createdAt: user.createdAt,
          }
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

  app.get("/api/user", authenticateRequest, (req, res) => {
    if (!req.user) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    return res.json({
      id: req.user.id,
      username: req.user.username,
      email: req.user.email,
      ssid: req.user.ssid,
      createdAt: req.user.createdAt,
    });
  });
}

// Token verification middleware
export function verifyToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return next(); // Continue to session-based auth if no token
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as any;
    req.user = {
      id: decoded.id,
      username: decoded.username,
      ssid: decoded.ssid
    } as Express.User;
    req.token = token;
    next();
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      return res.status(401).json({ error: "Token expired" });
    }
    next(); // Continue to session-based auth if token is invalid
  }
}

/**
 * authenticateRequest
 * Middleware to ensure user is logged in for dashboard access
 * Supports both JWT and session-based authentication
 */
export function authenticateRequest(req: Request, res: Response, next: NextFunction) {
  if (req.user) {
    return next();
  }
  return res.status(401).json({ error: "Authentication required" });
}