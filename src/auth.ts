import type { Context, MiddlewareHandler } from 'hono'
import type { AppEnv } from './app'
import * as jose from 'jose'

// =============================================================================
// Auth Context Accessor
// =============================================================================

export const isAdmin = (c: Context<AppEnv>): boolean => {
  return c.get('isAdmin') ?? false
}

// =============================================================================
// Auth Middleware
// =============================================================================

export const authMiddleware = (): MiddlewareHandler<AppEnv> => {
  return async (c, next) => {
    const adminSecret = c.env.ADMIN_JWT_SECRET
    const userSecret = c.env.USER_JWT_SECRET

    // Support both Authorization header and query param (for backward compat)
    const authHeader = c.req.header('Authorization')
    const token = authHeader?.startsWith('Bearer ')
      ? authHeader.slice('Bearer '.length).trim()
      : c.req.query('auth_token')

    if (!token) {
      return c.json({ error: 'Missing authentication token' }, 401)
    }

    // Try admin secret first
    try {
      await verifyToken(token, adminSecret)
      c.set('isAdmin', true)
      await next()
      return
    } catch {
      // Not an admin token, try user secret
    }

    // Try user secret
    try {
      await verifyToken(token, userSecret)
      c.set('isAdmin', false)
      await next()
      return
    } catch {
      // Neither admin nor user token
    }

    return c.json({ error: 'Invalid authentication token' }, 401)
  }
}

// =============================================================================
// Token Verification
// =============================================================================

const verifyToken = async (token: string, secret: string): Promise<void> => {
  const sec = jose.base64url.decode(secret)

  await jose.jwtVerify(token, sec, {
    issuer: 'wcp',
    audience: 'wcp',
  })
}

// =============================================================================
// Token Generation (for upstream services)
// =============================================================================

export const generateToken = async (secret: string, expiry: string): Promise<string> => {
  const sec = jose.base64url.decode(secret)

  const token = await new jose.SignJWT({})
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setIssuer('wcp')
    .setAudience('wcp')
    .setExpirationTime(expiry)
    .sign(sec)

  return token
}
