import { pgTable, text, serial, integer, timestamp, jsonb, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { relations } from "drizzle-orm";
import { users } from "./schema";

// Table for storing user credits
export const userCredits = pgTable("user_credits", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  balance: integer("balance").notNull().default(0),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// Table for storing credit packages that users can purchase
export const creditPackages = pgTable("credit_packages", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  credits: integer("credits").notNull(),
  price: integer("price").notNull(), // Price in cents
  description: text("description"),
  active: boolean("active").notNull().default(true),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Table for storing payment methods (bKash, Nagad, Bank Transfer)
export const paymentMethods = pgTable("payment_methods", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  instructions: text("instructions").notNull(),
  accountDetails: jsonb("account_details").$type<Record<string, any>>().notNull(),
  active: boolean("active").notNull().default(true),
});

export type PaymentMethod = typeof paymentMethods.$inferSelect;

// Table for storing payment transactions
export const payments = pgTable("payments", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  packageId: integer("package_id").references(() => creditPackages.id).notNull(),
  paymentMethodId: integer("payment_method_id").references(() => paymentMethods.id).notNull(),
  amount: integer("amount").notNull(), // Amount in BDT
  status: text("status").notNull(), // 'pending', 'pending_verification', 'verified', 'rejected'
  transactionId: text("transaction_id"), // bKash/Nagad transaction ID or bank reference
  senderNumber: text("sender_number"), // Mobile number for bKash/Nagad
  verifiedAt: timestamp("verified_at"),
  verifiedBy: integer("verified_by").references(() => users.id),
  metadata: jsonb("metadata").$type<Record<string, any>>(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Table for tracking credit usage
export const creditUsage = pgTable("credit_usage", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").references(() => users.id).notNull(),
  amount: integer("amount").notNull(),
  type: text("type").notNull(), // 'search', 'scan', etc.
  metadata: jsonb("metadata").$type<Record<string, any>>(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// Relations
export const userCreditsRelations = relations(userCredits, ({ one }) => ({
  user: one(users, {
    fields: [userCredits.userId],
    references: [users.id],
  }),
}));

export const paymentsRelations = relations(payments, ({ one }) => ({
  user: one(users, {
    fields: [payments.userId],
    references: [users.id],
  }),
  package: one(creditPackages, {
    fields: [payments.packageId],
    references: [creditPackages.id],
  }),
}));

// Schemas for inserting/updating data
export const insertCreditPackageSchema = createInsertSchema(creditPackages, {
  name: z.string().min(1),
  credits: z.number().positive(),
  price: z.number().positive(),
  description: z.string().optional(),
  active: z.boolean().optional(),
}).omit({
  id: true,
  createdAt: true,
});

export const insertPaymentSchema = createInsertSchema(payments).omit({
  id: true,
  createdAt: true,
});

export const insertCreditUsageSchema = createInsertSchema(creditUsage).omit({
  id: true,
  createdAt: true,
});

// TypeScript types
export type InsertCreditPackage = z.infer<typeof insertCreditPackageSchema>;
export type CreditPackage = typeof creditPackages.$inferSelect;
export type Payment = typeof payments.$inferSelect;
export type CreditUsage = typeof creditUsage.$inferSelect;
export type UserCredits = typeof userCredits.$inferSelect;
