import assert from "node:assert/strict";
import { test } from "node:test";
import {
  collectorIdSchema,
  enrollBodySchema,
  heartbeatBodySchema,
} from "./contract";

test("collector contract rejects arbitrary execution identifiers", () => {
  assert.equal(collectorIdSchema.safeParse("SYSTEM_INFO").success, true);
  assert.equal(collectorIdSchema.safeParse("RUN_SHELL").success, false);
});

test("enrollment contract rejects unsupported operating systems", () => {
  const parsed = enrollBodySchema.safeParse({
    code: "ABCDE-ABCDE-ABCDE-ABCDE-ABCDE",
    agentVersion: "0.1.0",
    osType: "LINUX",
    system: {
      hostname: "host",
      osName: "Linux",
      osVersion: "1",
      architecture: "amd64",
    },
  });
  assert.equal(parsed.success, false);
});

test("heartbeat contract requires a bounded request id and offset timestamp", () => {
  assert.equal(
    heartbeatBodySchema.safeParse({
      requestId: "request-1",
      agentVersion: "0.1.0",
      timestamp: "2026-11-04T12:00:00Z",
      collectorErrors: [],
    }).success,
    true,
  );
  assert.equal(
    heartbeatBodySchema.safeParse({
      requestId: "",
      agentVersion: "0.1.0",
      timestamp: "not-a-date",
    }).success,
    false,
  );
});
