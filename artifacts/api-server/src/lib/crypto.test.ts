import assert from "node:assert/strict";
import { test } from "node:test";
import {
  generateEnrollmentCode,
  normalizeEnrollmentCode,
  randomToken,
  sha256Hex,
} from "./crypto";

test("enrollment codes use the documented unambiguous format", () => {
  const codes = new Set(
    Array.from({ length: 100 }, () => generateEnrollmentCode()),
  );
  assert.equal(codes.size, 100);
  for (const code of codes)
    assert.match(code, /^[A-HJ-NP-Z2-9]{5}(?:-[A-HJ-NP-Z2-9]{5}){4}$/);
});

test("normalization is separator and case insensitive", () => {
  assert.equal(normalizeEnrollmentCode("ab-cd 23"), "ABCD23");
});

test("device tokens and hashes are non-empty and stable", () => {
  const token = randomToken(32);
  assert.ok(token.length >= 43);
  assert.equal(sha256Hex(token), sha256Hex(token));
});
