import { pgTable, text, serial, timestamp, integer } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";
import { z } from "zod";
import { nanoid } from 'nanoid';

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull(),
  email: text("email"),
  password: text("password"),
  firebaseUid: text("firebase_uid").unique(),
  ssid: text("ssid").unique().notNull().$defaultFn(() => nanoid(12)),
  apiKey: text("api_key").unique(), 
  createdAt: timestamp("created_at").defaultNow(),
});

export const links = pgTable("links", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  originalUrl: text("original_url").notNull(),
  rewrittenUrl: text("rewritten_url").notNull(),
  source: text("source").notNull(),
  clicks: integer("clicks").default(0),
  createdAt: timestamp("created_at").defaultNow(),
});

// Create base schemas
const baseInsertUser = createInsertSchema(users);
const baseSelectUser = createSelectSchema(users);

// Extend with custom validation
export const insertUserSchema = baseInsertUser.extend({
  username: z.string().min(1, "Username is required"),
  email: z.string().email("Invalid email").optional(),
  password: z.string().min(6, "Password must be at least 6 characters").optional(),
});

export const selectUserSchema = baseSelectUser;
export const insertLinkSchema = createInsertSchema(links);
export const selectLinkSchema = createSelectSchema(links);

export type InsertUser = typeof users.$inferInsert;
export type SelectUser = typeof users.$inferSelect;
export type InsertLink = typeof links.$inferInsert;
export type SelectLink = typeof links.$inferSelect;