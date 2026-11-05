import assert from "node:assert/strict";
import { once } from "node:events";
import { test } from "node:test";
import app from "./app";

test("liveness remains available while dependent routes fail closed", async (t) => {
  const environmentNames = [
    "SUPABASE_DB_URL",
    "DATABASE_URL",
    "CLERK_PUBLISHABLE_KEY",
    "CLERK_SECRET_KEY",
  ] as const;
  const saved = Object.fromEntries(
    environmentNames.map((name) => [name, process.env[name]]),
  );

  for (const name of environmentNames) delete process.env[name];

  const server = app.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => {
    server.close();
    for (const name of environmentNames) {
      const value = saved[name];
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });

  const address = server.address();
  assert(address && typeof address === "object");
  const origin = `http://127.0.0.1:${address.port}`;

  const healthResponse = await fetch(`${origin}/api/healthz`);
  assert.equal(healthResponse.status, 200);
  assert.deepEqual(await healthResponse.json(), { status: "ok" });

  const protectedResponse = await fetch(`${origin}/api/devices`);
  assert.equal(protectedResponse.status, 503);
  assert.deepEqual(await protectedResponse.json(), {
    error: "Staging service configuration is incomplete",
    details: {
      missing: ["SUPABASE_DB_URL", "CLERK_PUBLISHABLE_KEY", "CLERK_SECRET_KEY"],
    },
  });
});
