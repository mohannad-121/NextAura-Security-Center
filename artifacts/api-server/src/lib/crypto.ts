import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

/** Human-friendly enrollment code: 5 groups of 5 chars from an unambiguous alphabet. */
export function generateEnrollmentCode(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const buf = randomBytes(25);
  let out = "";
  for (let i = 0; i < 25; i++) {
    if (i > 0 && i % 5 === 0) out += "-";
    out += alphabet[buf[i]! % alphabet.length];
  }
  return out;
}

export function normalizeEnrollmentCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z0-9]/g, "");
}

export function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
}
