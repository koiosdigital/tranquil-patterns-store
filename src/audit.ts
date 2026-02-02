/**
 * Audit logging for device pattern downloads.
 * Logs are stored in KV with prefix 'audit:'.
 */

export type AuditEvent = 'request_encrypted' | 'download_encrypted'

interface AuditEntry {
  event: AuditEvent
  device_cn: string
  pattern_uuid: string
  timestamp: number
  ip?: string
}

/**
 * Log an audit event.
 */
export async function logAudit(
  kv: KVNamespace,
  event: AuditEvent,
  deviceCn: string,
  patternUuid: string,
  ip?: string
): Promise<void> {
  const timestamp = Date.now()
  const entryId = `${timestamp}-${crypto.randomUUID().slice(0, 8)}`
  const key = `audit:${deviceCn}:${entryId}`

  const entry: AuditEntry = {
    event,
    device_cn: deviceCn,
    pattern_uuid: patternUuid,
    timestamp,
    ip,
  }

  // Store with 30 day TTL
  await kv.put(key, JSON.stringify(entry), {
    expirationTtl: 30 * 24 * 60 * 60, // 30 days
  })
}
