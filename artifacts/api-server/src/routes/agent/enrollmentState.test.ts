import assert from "node:assert/strict";
import { test } from "node:test";
import { enrollmentState } from "./enrollmentState";

const future = new Date("2030-01-01T00:00:00Z");
const past = new Date("2020-01-01T00:00:00Z");
const now = new Date("2026-11-04T00:00:00Z").getTime();

test("valid pending enrollment succeeds state validation", () => {
  assert.equal(
    enrollmentState({ status: "PENDING", expiresAt: future }, now),
    "VALID",
  );
});

test("expired enrollment fails state validation", () => {
  assert.equal(
    enrollmentState({ status: "PENDING", expiresAt: past }, now),
    "EXPIRED",
  );
  assert.equal(
    enrollmentState({ status: "EXPIRED", expiresAt: future }, now),
    "EXPIRED",
  );
});

test("reused and cancelled enrollment codes fail state validation", () => {
  assert.equal(
    enrollmentState({ status: "CONSUMED", expiresAt: future }, now),
    "USED",
  );
  assert.equal(
    enrollmentState({ status: "CANCELLED", expiresAt: future }, now),
    "CANCELLED",
  );
});
