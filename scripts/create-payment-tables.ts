import { db } from "../server/db";
import { sql } from "drizzle-orm";

async function createPaymentTables() {
  try {
    // Create credit_packages table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS credit_packages (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        credits INTEGER NOT NULL,
        price INTEGER NOT NULL,
        description TEXT,
        active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);

    // Create payment_methods table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS payment_methods (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        instructions TEXT NOT NULL,
        account_details JSONB NOT NULL,
        active BOOLEAN NOT NULL DEFAULT true
      );
    `);

    // Create user_credits table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS user_credits (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        balance INTEGER NOT NULL DEFAULT 0,
        updated_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);

    // Create payments table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        package_id INTEGER NOT NULL REFERENCES credit_packages(id),
        payment_method_id INTEGER NOT NULL REFERENCES payment_methods(id),
        amount INTEGER NOT NULL,
        status TEXT NOT NULL,
        transaction_id TEXT,
        sender_number TEXT,
        verified_at TIMESTAMP,
        verified_by INTEGER REFERENCES users(id),
        metadata JSONB,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);

    // Create credit_usage table
    await db.execute(sql`
      CREATE TABLE IF NOT EXISTS credit_usage (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        amount INTEGER NOT NULL,
        type TEXT NOT NULL,
        metadata JSONB,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);

    console.log("Payment tables created successfully");
    process.exit(0);
  } catch (error) {
    console.error("Error creating payment tables:", error);
    process.exit(1);
  }
}

createPaymentTables();
