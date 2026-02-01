import type { Context } from 'hono'
import type { CloudflareBindings } from './types'

export type AppEnv = {
  Bindings: CloudflareBindings
  Variables: {
    isAdmin: boolean
  }
}

export type ErrorStatus = 400 | 401 | 403 | 404 | 500

export const jsonError = (c: Context, status: ErrorStatus, message: string) =>
  c.json({ error: message }, status)
