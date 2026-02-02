import { Hono } from 'hono'
import { Buffer } from 'node:buffer'
import { z } from 'zod'
import { type AppEnv, jsonError } from '../app'
import { type Pattern, postPatternBodySchema, uuidSchema, paginationQuerySchema } from '../types'
import * as auth from '../auth'
import {
  extractDevicePublicKey,
  extractDeviceCn,
  encryptPattern,
  buildEncryptedPatternFile,
  arrayBufferToBase64,
  buildThrbFile,
  isThrbFile,
  extractThrbPoints,
} from '../crypto'
import { checkRateLimit, recordRequest } from '../ratelimit'
import { logAudit } from '../audit'

const patterns = new Hono<AppEnv>()

patterns.get('/', auth.authMiddleware(), async (c) => {
  const query = paginationQuerySchema.safeParse({
    page: c.req.query('page'),
    per_page: c.req.query('per_page'),
  })

  const { page, per_page } = query.success ? query.data : { page: 1, per_page: 20 }
  const offset = (page - 1) * per_page

  // Get total count
  const countStmt = c.env.database.prepare('SELECT COUNT(*) as total FROM patterns')
  const countResult = await countStmt.first<{ total: number }>()
  const total = countResult?.total ?? 0

  // Get paginated results
  const stmt = c.env.database
    .prepare('SELECT * FROM patterns ORDER BY popularity DESC LIMIT ? OFFSET ?')
    .bind(per_page, offset)
  const { results }: { results: Pattern[] } = await stmt.all()

  return c.json({
    data: results,
    pagination: {
      total,
      page,
      per_page,
      total_pages: Math.ceil(total / per_page),
    },
  })
})

patterns.get('/:uuid', auth.authMiddleware(), async (c) => {
  const uuidResult = uuidSchema.safeParse(c.req.param('uuid'))
  if (!uuidResult.success) {
    return jsonError(c, 400, 'Invalid UUID format')
  }

  const stmt = c.env.database.prepare('SELECT * FROM patterns WHERE uuid=?').bind(uuidResult.data)
  const pattern: Pattern | null = await stmt.first()

  if (!pattern) {
    return jsonError(c, 404, 'Pattern not found')
  }

  c.header('Cache-Control', 'public, max-age=31536000')
  return c.json(pattern)
})

patterns.get('/:uuid/thumb.png', auth.authMiddleware(), async (c) => {
  const uuidResult = uuidSchema.safeParse(c.req.param('uuid'))
  if (!uuidResult.success) {
    return jsonError(c, 400, 'Invalid UUID format')
  }

  const objectName = `patterns/thumbs/${uuidResult.data}.png`
  const object = await c.env.bucket.get(objectName)

  if (!object) {
    return jsonError(c, 404, 'Thumbnail not found')
  }

  const objectContent = await object.arrayBuffer()
  c.header('Content-Type', 'image/png')
  c.header('Cache-Control', 'public, max-age=31536000')

  return c.body(objectContent)
})

const encryptedPatternRequestSchema = z.object({
  pem: z.string().min(1, 'pem is required'),
})

// Download token format: {uuid}-{randomHex}
const downloadTokenSchema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}-[0-9a-f]{16}$/i)

patterns.get('/download/:token', async (c) => {
  const tokenResult = downloadTokenSchema.safeParse(c.req.param('token'))
  if (!tokenResult.success) {
    return jsonError(c, 400, 'Invalid download token')
  }

  const token = tokenResult.data.toLowerCase()
  const objectName = `encrypted/${token}.dat`
  const object = await c.env.bucket.get(objectName)

  if (!object) {
    return jsonError(c, 404, 'Encrypted pattern not found or expired')
  }

  // Get device CN from R2 custom metadata for rate limiting and audit
  const deviceCn = object.customMetadata?.device_cn
  const patternUuid = object.customMetadata?.pattern_uuid

  if (deviceCn) {
    // Check rate limit before serving
    const rateLimitResult = await checkRateLimit(c.env.audit_kv, deviceCn)
    if (!rateLimitResult.allowed) {
      c.header('Retry-After', String(rateLimitResult.retryAfter ?? 60))
      return jsonError(c, 429, rateLimitResult.error ?? 'Rate limit exceeded')
    }

    // Record this request for rate limiting
    await recordRequest(c.env.audit_kv, deviceCn)

    // Log audit event
    const clientIp = c.req.header('CF-Connecting-IP') ?? c.req.header('X-Forwarded-For')
    await logAudit(c.env.audit_kv, 'download_encrypted', deviceCn, patternUuid ?? token, clientIp)
  }

  const data = await object.arrayBuffer()

  // Delete the file after reading (one-time download)
  await c.env.bucket.delete(objectName)

  c.header('Content-Type', 'application/octet-stream')
  c.header('Content-Disposition', `attachment; filename="${token}.dat"`)

  return c.body(data)
})

patterns.post('/:uuid/encrypted', auth.authMiddleware(), async (c) => {
  if (!auth.isAdmin(c)) {
    return jsonError(c, 403, 'Admin access required')
  }

  const uuidResult = uuidSchema.safeParse(c.req.param('uuid'))
  if (!uuidResult.success) {
    return jsonError(c, 400, 'Invalid UUID format')
  }

  let json: unknown
  try {
    json = await c.req.json()
  } catch {
    return jsonError(c, 400, 'Request body must be valid JSON')
  }

  const bodyResult = encryptedPatternRequestSchema.safeParse(json)
  if (!bodyResult.success) {
    const message = bodyResult.error.issues[0]?.message ?? 'Invalid request body'
    return jsonError(c, 400, message)
  }

  const { pem } = bodyResult.data
  const patternUuid = uuidResult.data

  // Extract device CN and public key from certificate chain
  let devicePublicKey: CryptoKey
  let deviceCn: string
  try {
    deviceCn = extractDeviceCn(pem)
    devicePublicKey = await extractDevicePublicKey(pem)
  } catch (e) {
    const message = e instanceof Error ? e.message : 'Failed to extract device public key'
    return jsonError(c, 400, message)
  }

  // Log audit event for encrypted pattern request
  const clientIp = c.req.header('CF-Connecting-IP') ?? c.req.header('X-Forwarded-For')
  await logAudit(c.env.audit_kv, 'request_encrypted', deviceCn, patternUuid, clientIp)

  // Fetch THRB pattern from R2 (stored as .dat binary file)
  const objectName = `patterns/${patternUuid}.dat`
  const object = await c.env.bucket.get(objectName)
  if (!object) {
    return jsonError(c, 404, 'Pattern not found')
  }

  // Read THRB file and extract binary points for encryption
  const thrbData = new Uint8Array(await object.arrayBuffer())
  if (!isThrbFile(thrbData)) {
    return jsonError(c, 500, 'Pattern is not in THRB format')
  }
  const { points: patternData } = extractThrbPoints(thrbData)

  // Encrypt pattern for this device
  let encryptedFile: Uint8Array
  let originalHash: Uint8Array
  let originalSize: number
  let pointCount: number
  try {
    const encryptionResult = await encryptPattern(patternData, devicePublicKey)
    encryptedFile = buildEncryptedPatternFile(encryptionResult)
    originalHash = encryptionResult.originalHash
    originalSize = encryptionResult.originalSize
    pointCount = encryptionResult.pointCount
  } catch (e) {
    console.error('Encryption error:', e)
    const message = e instanceof Error ? e.message : 'Failed to encrypt pattern'
    return jsonError(c, 500, message)
  }

  // Generate random suffix for encrypted file
  const randomBytes = crypto.getRandomValues(new Uint8Array(8))
  const randomHex = Array.from(randomBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
  const encryptedObjectName = `encrypted/${patternUuid}-${randomHex}.dat`

  // Store encrypted file in R2 with device metadata for audit/rate limiting
  try {
    await c.env.bucket.put(encryptedObjectName, encryptedFile, {
      httpMetadata: {
        contentType: 'application/octet-stream',
      },
      customMetadata: {
        device_cn: deviceCn,
        pattern_uuid: patternUuid,
      },
    })
  } catch (e) {
    console.error('R2 upload error:', e)
    return jsonError(c, 500, 'Failed to store encrypted pattern')
  }

  // Generate download token (the random suffix serves as the token)
  // URL format: /patterns/download/{patternUuid}-{randomHex}
  const downloadToken = `${patternUuid}-${randomHex}`

  return c.json({
    success: true,
    download_url: `/patterns/download/${downloadToken}`,
    pattern_uuid: patternUuid,
    encryption: {
      original_size: originalSize,
      original_hash: arrayBufferToBase64(originalHash.buffer as ArrayBuffer),
      point_count: pointCount,
    },
  })
})

patterns.post('/', auth.authMiddleware(), async (c) => {
  if (!auth.isAdmin(c)) {
    return jsonError(c, 403, 'Admin access required')
  }

  let json: unknown
  try {
    json = await c.req.json()
  } catch {
    return jsonError(c, 400, 'Request body must be valid JSON')
  }

  const bodyResult = postPatternBodySchema.safeParse(json)
  if (!bodyResult.success) {
    const message = bodyResult.error.issues[0]?.message ?? 'Invalid request body'
    return jsonError(c, 400, message)
  }

  const { patternData, pattern, thumbData } = bodyResult.data

  // Convert text pattern to THRB binary format
  const thrbFile = buildThrbFile(patternData)
  const sizeBytes = thrbFile.length

  // Store pattern as THRB .dat file
  try {
    const objectName = `patterns/${pattern.uuid}.dat`
    await c.env.bucket.put(objectName, thrbFile, {
      httpMetadata: { contentType: 'application/octet-stream' },
    })
  } catch {
    return jsonError(c, 500, 'Failed to store pattern data')
  }

  // Store thumbnail
  try {
    const objectName = `patterns/thumbs/${pattern.uuid}.png`
    const buf = Buffer.from(thumbData, 'base64')
    await c.env.bucket.put(objectName, buf)
  } catch {
    return jsonError(c, 500, 'Failed to store pattern thumbnail')
  }

  // Insert metadata with new schema fields
  const now = new Date().toISOString()
  const stmt = c.env.database
    .prepare(
      `INSERT INTO patterns (uuid, name, creator, date, popularity, reversible, start_point, encrypted, size_bytes, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      pattern.uuid,
      pattern.name,
      pattern.creator ?? 'Uploaded',
      pattern.date ?? now,
      pattern.popularity ?? 0,
      pattern.reversible ?? 0,
      pattern.start_point ?? 0,
      pattern.encrypted ?? 0,
      sizeBytes,
      now
    )

  try {
    const results = await stmt.run()
    return c.json({ uuid: pattern.uuid, meta: results.meta })
  } catch (e) {
    const message = e instanceof Error ? e.message : 'Database error'
    return jsonError(c, 500, message)
  }
})

export default patterns
