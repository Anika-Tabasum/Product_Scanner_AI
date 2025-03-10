import { defineConfig } from "drizzle-kit";
<<<<<<< HEAD
import dotenv from "dotenv"

dotenv.config();
=======
>>>>>>> e6c0e49 (admin fix)

if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL, ensure the database is provisioned");
}

export default defineConfig({
  out: "./migrations",
  schema: "./shared/schema.ts",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL,
  },
});
