import assert from "node:assert/strict";
import { afterEach, test } from "node:test";
import { agentPublicBaseUrl } from "./publicBaseUrl";

const originalEnv = { ...process.env };
afterEach(() => {
  process.env = { ...originalEnv };
});

function request(headers: Record<string, string> = {}, protocol = "https") {
  return {
    protocol,
    get(name: string): string | undefined {
      return headers[name.toLowerCase()];
    },
  };
}

test("production requires a configured canonical origin", () => {
  process.env.NODE_ENV = "production";
  delete process.env.AGENT_PUBLIC_BASE_URL;
  assert.throws(() => agentPublicBaseUrl(request()), /required in production/);
});

test("production ignores forwarded host when canonical origin is configured", () => {
  process.env.NODE_ENV = "production";
  process.env.AGENT_PUBLIC_BASE_URL = "https://security.example.com/";
  assert.equal(
    agentPublicBaseUrl(request({ "x-forwarded-host": "attacker.example" })),
    "https://security.example.com",
  );
});

test("configured origins reject insecure remote HTTP and URL paths", () => {
  process.env.NODE_ENV = "development";
  process.env.AGENT_PUBLIC_BASE_URL = "http://security.example.com";
  assert.throws(() => agentPublicBaseUrl(request()), /must use https/);
  process.env.AGENT_PUBLIC_BASE_URL = "https://security.example.com/api";
  assert.throws(() => agentPublicBaseUrl(request()), /must be an origin/);
});

test("development permits loopback HTTP only", () => {
  process.env.NODE_ENV = "development";
  delete process.env.AGENT_PUBLIC_BASE_URL;
  assert.equal(
    agentPublicBaseUrl(request({ host: "localhost:3000" }, "http")),
    "http://localhost:3000",
  );
});
