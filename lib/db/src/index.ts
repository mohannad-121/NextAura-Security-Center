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

export const databaseProvider: "supabase" | "generic" = process.env
  .SUPABASE_DB_URL
  ? "supabase"
  : "generic";

export const pool = new Pool({
  connectionString,
  // A Vercel deployment can scale to multiple instances. Keep each instance's
  // pool deliberately small and use the Supabase transaction pooler URL.
  max: process.env.VERCEL ? 2 : 8,
  connectionTimeoutMillis: 10_000,
  idleTimeoutMillis: 30_000,
  allowExitOnIdle: true,
});
export const db = drizzle(pool, { schema });

export * from "./schema";
