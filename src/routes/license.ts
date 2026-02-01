import { Hono } from 'hono'
import { z } from 'zod'
import { type AppEnv, jsonError } from '../app'
import * as auth from '../auth'
import { type LicensePayload, signLicense } from '../crypto'

const license = new Hono<AppEnv>()

const licenseRequestSchema = z.object({
  device_id: z.string().min(1, 'device_id is required'),
})

license.post('/', auth.authMiddleware(), async (c) => {
  if (!auth.isAdmin(c)) {
    return jsonError(c, 403, 'Admin access required')
  }

  let json: unknown
  try {
    json = await c.req.json()
  } catch {
    return jsonError(c, 400, 'Request body must be valid JSON')
  }

  const bodyResult = licenseRequestSchema.safeParse(json)
  if (!bodyResult.success) {
    const message = bodyResult.error.issues[0]?.message ?? 'Invalid request body'
    return jsonError(c, 400, message)
  }

  const { device_id } = bodyResult.data

  const now = Math.floor(Date.now() / 1000)
  const oneMonthSeconds = 30 * 24 * 60 * 60

  // Generate unique license ID
  const randomBytes = crypto.getRandomValues(new Uint8Array(4))
  const randomHex = Array.from(randomBytes)
    .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
    .join('')
  const licenseId = `LIC-${now}-${randomHex}`

  const licensePayload: LicensePayload = {
    for_device: device_id,
    max_patterns: 100,
    valid_from: now,
    valid_to: now + oneMonthSeconds,
    license_id: licenseId,
    issued_at: now,
  }

  try {
    const signature = await signLicense(licensePayload, c.env.LICENSE_SIGNING_KEY)

    return c.json({
      success: true,
      license: licensePayload,
      signature,
      server_timestamp: now,
    })
  } catch (e) {
    console.error('License signing error:', e)
    const message = e instanceof Error ? e.message : 'Failed to sign license'
    return jsonError(c, 500, message)
  }
})

export default license
