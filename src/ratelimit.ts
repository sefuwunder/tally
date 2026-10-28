// Tally ERP — ratelimit.ts
// In-memory per-IP fixed-window limiter for auth endpoints (Phase 10
// security pass). One instance per server (createServer closure), so
// test servers are isolated and no global reset hook is needed.
// Limit is env-overridable via TALLY_AUTH_RATE_LIMIT (see
// sessionConfigFromEnv); tests pass a low limit through SessionConfig.

export interface RateLimiter {
  /** True if this attempt is within the limit; false => respond 429. */
  allow(ip: string): { allowed: boolean; retryAfterSeconds: number };
  reset(): void;
}

export function createRateLimiter(limitPerMinute: number, windowMs = 60_000): RateLimiter {
  const limit = Math.max(1, Math.floor(limitPerMinute) || 1);
  const buckets = new Map<string, { count: number; windowStart: number }>();
  return {
    allow(ip: string) {
      const now = Date.now();
      const key = ip || "unknown";
      const bucket = buckets.get(key);
      if (!bucket || now - bucket.windowStart >= windowMs) {
        buckets.set(key, { count: 1, windowStart: now });
        return { allowed: true, retryAfterSeconds: 0 };
      }
      if (bucket.count < limit) {
        bucket.count += 1;
        return { allowed: true, retryAfterSeconds: 0 };
      }
      const retryAfterSeconds = Math.max(
        1,
        Math.ceil((windowMs - (now - bucket.windowStart)) / 1000),
      );
      return { allowed: false, retryAfterSeconds };
    },
    reset() {
      buckets.clear();
    },
  };
}
