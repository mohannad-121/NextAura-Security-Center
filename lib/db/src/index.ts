import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

/**
 * SUPABASE_DB_URL (the customer's Supabase Postgres) takes precedence over the
 * platform-provisioned DATABASE_URL so the same code runs against either.
 */
const connectionString =
  process.env.SUPABASE_DB_URL || process.env.DATABASE_URL;
if (!connectionString) {
  throw new Error("SUPABASE_DB_URL or DATABASE_URL must be set.");
}

export const databaseProvider: "supabase" | "replit" = process.env
  .SUPABASE_DB_URL
  ? "supabase"
  : "replit";

export const pool = new Pool({
  connectionString,
  max: 8,
});
export const db = drizzle(pool, { schema });

export * from "./schema";
