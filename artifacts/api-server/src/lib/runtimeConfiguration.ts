import type { RequestHandler } from "express";

type RuntimeEnvironment = NodeJS.ProcessEnv;

export function missingDatabaseConfiguration(
  env: RuntimeEnvironment = process.env,
): string[] {
  return env.SUPABASE_DB_URL || env.DATABASE_URL ? [] : ["SUPABASE_DB_URL"];
}

export function missingOperatorConfiguration(
  env: RuntimeEnvironment = process.env,
): string[] {
  const missing = missingDatabaseConfiguration(env);
  if (!env.CLERK_PUBLISHABLE_KEY) missing.push("CLERK_PUBLISHABLE_KEY");
  if (!env.CLERK_SECRET_KEY) missing.push("CLERK_SECRET_KEY");
  return missing;
}

export function requireRuntimeConfiguration(
  required: (env?: RuntimeEnvironment) => string[],
): RequestHandler {
  return (_req, res, next) => {
    const missing = required();
    if (missing.length === 0) {
      next();
      return;
    }

    res.status(503).json({
      error: "Staging service configuration is incomplete",
      details: { missing },
    });
  };
}
