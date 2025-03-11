import { pgTable, text, serial, jsonb, timestamp, boolean, integer } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { relations } from "drizzle-orm";

export const users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  email: text("email").notNull().unique(),
  password: text("password").notNull(),
  isVerified: text("is_verified").default("false"),
  verificationToken: text("verification_token"),
  resetToken: text("reset_token"),
  role: text("role").default("user").notNull(),
  profilePicture: text("profile_picture"),
  deleted: boolean("deleted").default(false).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const products = pgTable("products", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  brand: text("brand"),
  category: text("category"),
  identifiedText: text("identified_text"),
  imageUrl: text("image_url"),
  metadata: jsonb("metadata").$type<Record<string, any>>(),
  userId: serial("user_id").references(() => users.id),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const ggsData = pgTable("ggs_data", {
  id: serial("id").primaryKey(),
  originalId: integer("original_id").notNull(),
  sex: integer("sex").notNull(), 
  generations: integer("generations").notNull(),
  eduLevel: integer("edu_level").notNull(),
  age: integer("age").notNull(),
  eventData: jsonb("event_data").$type<Record<string, string>>(), 
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const usersRelations = relations(users, ({ many }) => ({
  products: many(products),
}));

export const productsRelations = relations(products, ({ one }) => ({
  user: one(users, {
    fields: [products.userId],
    references: [users.id],
  }),
}));

export const insertUserSchema = createInsertSchema(users, {
  username: z.string().min(3).max(50),
  email: z.string().email(),
  password: z.string().min(6),
}).omit({ 
  id: true, 
  createdAt: true, 
  isVerified: true, 
  verificationToken: true, 
  resetToken: true,
  role: true, 
  profilePicture: true,
  deleted: true 
});

export const insertProductSchema = createInsertSchema(products).omit({ 
  id: true,
  userId: true,
  createdAt: true 
});

export const insertGGSDataSchema = createInsertSchema(ggsData).omit({
  id: true,
  createdAt: true,
});

export const updateProfileSchema = createInsertSchema(users).pick({ 
  profilePicture: true 
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type InsertProduct = z.infer<typeof insertProductSchema>;
export type Product = typeof products.$inferSelect;
export type UpdateProfile = z.infer<typeof updateProfileSchema>;
export type InsertGGSData = z.infer<typeof insertGGSDataSchema>;
export type GGSData = typeof ggsData.$inferSelect;