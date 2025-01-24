import { pgTable, text, serial, timestamp, integer, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";
import { nanoid } from 'nanoid';

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").unique().notNull(),
  password: text("password").notNull(),
  ssid: text("ssid").unique().notNull().$defaultFn(() => nanoid(12)),
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

export const insertUserSchema = createInsertSchema(users);
export const selectUserSchema = createSelectSchema(users);
export const insertLinkSchema = createInsertSchema(links);
export const selectLinkSchema = createSelectSchema(links);

export type InsertUser = typeof users.$inferInsert;
export type SelectUser = typeof users.$inferSelect;
export type InsertLink = typeof links.$inferInsert;
export type SelectLink = typeof links.$inferSelect;
