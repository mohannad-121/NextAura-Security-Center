import assert from "node:assert/strict";
import test from "node:test";

import {
  missingDatabaseConfiguration,
  missingOperatorConfiguration,
} from "./runtimeConfiguration";

test("database configuration accepts the Supabase pooler or generic fallback", () => {
  assert.deepEqual(missingDatabaseConfiguration({}), ["SUPABASE_DB_URL"]);
  assert.deepEqual(
    missingDatabaseConfiguration({ SUPABASE_DB_URL: "postgresql://staging" }),
    [],
  );
  assert.deepEqual(
    missingDatabaseConfiguration({ DATABASE_URL: "postgresql://staging" }),
    [],
  );
});

test("operator configuration reports names without exposing values", () => {
  assert.deepEqual(missingOperatorConfiguration({}), [
    "SUPABASE_DB_URL",
    "CLERK_PUBLISHABLE_KEY",
    "CLERK_SECRET_KEY",
  ]);
  assert.deepEqual(
    missingOperatorConfiguration({
      SUPABASE_DB_URL: "postgresql://staging",
      CLERK_PUBLISHABLE_KEY: "configured",
      CLERK_SECRET_KEY: "configured",
    }),
    [],
  );
});
