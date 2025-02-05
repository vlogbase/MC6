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

// Initialize Firebase Admin with enhanced error handling
const b64Secret = process.env.FIREBASE_SERVICE_ACCOUNT_JSON_B64;
if (!b64Secret) {
  throw new Error('FIREBASE_SERVICE_ACCOUNT_JSON_B64 environment variable is required');
}

// Initialize Firebase Admin using base64-encoded service account
try {
  // Decode the base64-encoded service account JSON
  const serviceAccountJson = Buffer.from(b64Secret, 'base64').toString('utf8');

  // Validate the decoded JSON string
  if (!serviceAccountJson || serviceAccountJson.trim() === '') {
    throw new Error("Empty or invalid base64 decoded content");
  }

  console.log('Attempting to parse service account JSON...');

  // Parse and validate the service account configuration
  const serviceAccount = JSON.parse(serviceAccountJson);

  // Validate required fields
  const requiredFields = ['project_id', 'private_key', 'client_email'];
  const missingFields = requiredFields.filter(field => !serviceAccount[field]);

  if (missingFields.length > 0) {
    throw new Error(`Missing required fields in service account: ${missingFields.join(', ')}`);
  }

  // Validate private key format
  if (!serviceAccount.private_key.includes('-----BEGIN PRIVATE KEY-----')) {
    throw new Error('Invalid private key format');
  }

  // Log initialization details (without sensitive data)
  console.log('Service account validation successful:', {
    project_id: serviceAccount.project_id,
    client_email: serviceAccount.client_email,
    private_key_length: serviceAccount.private_key?.length,
    has_valid_key_format: serviceAccount.private_key?.includes('-----BEGIN PRIVATE KEY-----')
  });

  // Initialize Firebase Admin SDK
  if (!admin.apps.length) {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log('Firebase Admin SDK initialized successfully');
  } else {
    console.log('Firebase Admin SDK already initialized');
  }

} catch (error: any) {
  console.error('Firebase Admin initialization error:', {
    name: error.name,
    message: error.message,
    stack: error.stack
  });

  if (error instanceof SyntaxError) {
    console.error('Failed to parse service account JSON. Check base64 encoding.');
  } else if (error.message.includes('invalid_grant')) {
    console.error('Invalid credentials. The service account key may have been revoked or is malformed.');
  } else if (error.message.includes('private_key')) {
    console.error('Private key validation failed. Check the key format.');
  }

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

  // Move sync endpoint outside of other auth routes for better visibility and access
  app.post("/api/sync-firebase-user", async (req: Request, res: Response) => {
    console.log('Sync endpoint called with body:', {
      hasIdToken: !!req.body?.idToken,
      contentType: req.headers['content-type']
    });

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
          email: decodedToken.email,
          token_issued_at: new Date(decodedToken.iat * 1000).toISOString(),
          token_expires_at: new Date(decodedToken.exp * 1000).toISOString()
        });
      } catch (verifyError: any) {
        console.error('Token verification failed:', {
          code: verifyError.code,
          message: verifyError.message,
          stack: verifyError.stack
        });
        return res.status(401).json({
          error: "Token verification failed",
          details: verifyError.message,
          code: verifyError.code
        });
      }

      const firebaseUid = decodedToken.uid;
      console.log('Looking up user with Firebase UID:', firebaseUid);

      // Look up existing user
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
          console.log('Created new user successfully:', {
            id: user.id,
            username: user.username,
            email: user.email
          });
        } catch (dbError) {
          console.error('Database insertion failed:', dbError);
          throw new Error('Failed to create user record');
        }
      } else {
        console.log('Found existing user:', {
          id: user.id,
          username: user.username,
          email: user.email
        });
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

      return res.json(responseData);
    } catch (error) {
      console.error('Error in sync endpoint:', error);
      let errorMessage = 'Failed to sync user';
      if (error instanceof Error) {
        errorMessage = error.message;
      }
      return res.status(500).json({ error: errorMessage });
    }
  });

  // Add a test endpoint to verify Firebase Admin SDK
  app.get("/api/test-firebase-admin", async (req, res) => {
    try {
      // List first few users from Firebase Auth
      const listUsersResult = await admin.auth().listUsers(1);
      res.json({
        status: 'success',
        message: 'Firebase Admin SDK is working',
        userCount: listUsersResult.users.length
      });
    } catch (error) {
      console.error('Firebase Admin test failed:', error);
      res.status(500).json({
        status: 'error',
        message: 'Firebase Admin SDK test failed',
        error: error instanceof Error ? error.message : 'Unknown error'
      });
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
  return app;
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