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
const b64Secret = process.env.FIREBASE_SERVICE_ACCOUNT_JSON_B64;
if (!b64Secret) {
  throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON_B64 environment variable is required');
}

// Initialize Firebase Admin using base64-encoded service account
try {
  // Decode the base64-encoded service account JSON
  const serviceAccountJson = Buffer.from(b64Secret, 'base64').toString('utf8');
  if (!serviceAccountJson) {
    throw new Error("Failed to decode Firebase service account JSON from base64");
  }

  const serviceAccount = JSON.parse(serviceAccountJson);
  if (!serviceAccount.project_id || !serviceAccount.private_key || !serviceAccount.client_email) {
    throw new Error("Invalid Firebase service account configuration");
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
  console.log('Firebase Admin initialized successfully with project:', serviceAccount.project_id);
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
        console.error('No ID token provided in sync request');
        return res.status(400).json({ error: "No ID token provided" });
      }

      console.log('Starting Firebase token verification process');
      let decodedToken;
      try {
        decodedToken = await admin.auth().verifyIdToken(idToken);
        console.log('Token verified successfully:', {
          uid: decodedToken.uid,
          email: decodedToken.email
        });
      } catch (verifyError: any) {
        console.error('Token verification failed:', verifyError.code, verifyError.message);
        return res.status(401).json({ 
          error: "Token verification failed",
          details: verifyError.message
        });
      }

      const firebaseUid = decodedToken.uid;
      console.log('Looking up user with Firebase UID:', firebaseUid);

      // Check if user exists in our database
      let [user] = await db
        .select()
        .from(users)
        .where(eq(users.firebaseUid, firebaseUid))
        .limit(1);

      if (!user) {
        console.log('Creating new user for Firebase UID:', firebaseUid);
        try {
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
          console.log('Created new user successfully:', user.username);
        } catch (dbError) {
          console.error('Database insertion failed:', dbError);
          throw new Error('Failed to create user record');
        }
      } else {
        console.log('Found existing user:', user.username);
      }

      const responseData = {
        id: user.id,
        username: user.username,
        email: user.email,
        ssid: user.ssid,
        apiKey: user.apiKey,
      };

      console.log('Sending user data response:', {
        ...responseData,
        apiKey: '***' // Mask API key in logs
      });

      res.json(responseData);
    } catch (error) {
      console.error('Error in sync endpoint:', error);
      let errorMessage = 'Failed to sync user';
      if (error instanceof Error) {
        errorMessage = error.message;
        if (error.message.includes('auth/id-token-expired')) {
          errorMessage = 'Authentication session expired. Please sign in again.';
        } else if (error.message.includes('auth/invalid-id-token')) {
          errorMessage = 'Invalid authentication token. Please sign in again.';
        }
      }
      res.status(500).json({ error: errorMessage });
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