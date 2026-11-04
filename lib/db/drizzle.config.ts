import { defineConfig } from "drizzle-kit";

const url = process.env.SUPABASE_DB_URL || process.env.DATABASE_URL;
if (!url) {
  throw new Error("SUPABASE_DB_URL or DATABASE_URL must be set");
}

export default defineConfig({
  schema: "./src/schema/*.ts",
  dialect: "postgresql",
  dbCredentials: { url },
});
