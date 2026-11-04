import type { RequestHandler } from "express";
import { tooMany } from "./errors";

interface Bucket { count: number; resetAt: number }

/** Simple in-memory fixed-window rate limiter keyed by a function of the request. */
export function rateLimit(opts: {
  windowMs: number;
  max: number;
  key: (req: Parameters<RequestHandler>[0]) => string;
}): RequestHandler {
  const buckets = new Map<string, Bucket>();
  setInterval(() => {
    const now = Date.now();
    for (const [k, b] of buckets) if (b.resetAt <= now) buckets.delete(k);
  }, opts.windowMs).unref();
  return (req, res, next) => {
    const key = opts.key(req);
    const now = Date.now();
    let b = buckets.get(key);
    if (!b || b.resetAt <= now) {
      b = { count: 0, resetAt: now + opts.windowMs };
      buckets.set(key, b);
    }
    b.count++;
    res.setHeader("X-RateLimit-Limit", String(opts.max));
    res.setHeader("X-RateLimit-Remaining", String(Math.max(0, opts.max - b.count)));
    if (b.count > opts.max) {
      res.setHeader("Retry-After", String(Math.ceil((b.resetAt - now) / 1000)));
      next(tooMany());
      return;
    }
    next();
  };
}
