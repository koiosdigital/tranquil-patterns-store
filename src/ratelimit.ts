/**
 * Rate limiting for device pattern downloads.
 * Limits: 20/min, 100/hr, 200/day per device CN.
 */

const LIMITS = {
  minute: { max: 20, windowMs: 60 * 1000 },
  hour: { max: 100, windowMs: 60 * 60 * 1000 },
  day: { max: 200, windowMs: 24 * 60 * 60 * 1000 },
} as const

type RateLimitWindow = keyof typeof LIMITS

interface RateLimitData {
  timestamps: number[]
}

/**
 * Check if a device CN is rate limited.
 * Returns null if allowed, or an error message if rate limited.
 */
export async function checkRateLimit(
  kv: KVNamespace,
  deviceCn: string
): Promise<{ allowed: boolean; error?: string; retryAfter?: number }> {
  const key = `ratelimit:${deviceCn}`
  const now = Date.now()

  // Get existing rate limit data
  const existing = await kv.get<RateLimitData>(key, 'json')
  const timestamps = existing?.timestamps ?? []

  // Filter to only timestamps within the largest window (day)
  const dayWindowStart = now - LIMITS.day.windowMs
  const recentTimestamps = timestamps.filter((ts) => ts > dayWindowStart)

  // Check each limit
  for (const [window, limit] of Object.entries(LIMITS) as [RateLimitWindow, (typeof LIMITS)[RateLimitWindow]][]) {
    const windowStart = now - limit.windowMs
    const countInWindow = recentTimestamps.filter((ts) => ts > windowStart).length

    if (countInWindow >= limit.max) {
      // Find oldest timestamp in this window to calculate retry-after
      const oldestInWindow = recentTimestamps.filter((ts) => ts > windowStart).sort((a, b) => a - b)[0]
      const retryAfter = oldestInWindow ? Math.ceil((oldestInWindow + limit.windowMs - now) / 1000) : 60

      return {
        allowed: false,
        error: `Rate limit exceeded: ${limit.max} requests per ${window}`,
        retryAfter,
      }
    }
  }

  return { allowed: true }
}

/**
 * Record a request for rate limiting purposes.
 */
export async function recordRequest(kv: KVNamespace, deviceCn: string): Promise<void> {
  const key = `ratelimit:${deviceCn}`
  const now = Date.now()

  // Get existing data
  const existing = await kv.get<RateLimitData>(key, 'json')
  const timestamps = existing?.timestamps ?? []

  // Filter to only timestamps within the largest window (day) + add current
  const dayWindowStart = now - LIMITS.day.windowMs
  const recentTimestamps = timestamps.filter((ts) => ts > dayWindowStart)
  recentTimestamps.push(now)

  // Store with TTL of 1 day
  await kv.put(key, JSON.stringify({ timestamps: recentTimestamps }), {
    expirationTtl: 86400, // 24 hours
  })
}
