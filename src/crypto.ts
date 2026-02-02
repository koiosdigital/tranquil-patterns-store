import * as x509 from '@peculiar/x509'

// =============================================================================
// Certificate Chain Parsing
// =============================================================================

/**
 * Extract the device public key from a base64-encoded PEM certificate chain.
 * Finds the leaf certificate where CN contains 'iotdevices.koiosdigital.net'.
 * @param pemChain - Base64-encoded PEM certificate chain
 */
export async function extractDevicePublicKey(pemChain: string): Promise<CryptoKey> {
  const rawPemChain = Buffer.from(pemChain, 'base64').toString('utf-8')
  // Split PEM chain into individual certificates
  const certPems = rawPemChain
    .split(/-----END CERTIFICATE-----/)
    .filter((s) => s.includes('-----BEGIN CERTIFICATE-----'))
    .map((s) => s.trim() + '\n-----END CERTIFICATE-----')

  if (certPems.length === 0) {
    throw new Error('No certificates found in PEM chain')
  }

  // Find the leaf certificate (CN contains iotdevices.koiosdigital.net)
  for (const pem of certPems) {
    const cert = new x509.X509Certificate(pem)
    const cn = cert.subject.match(/CN=([^,]+)/)?.[1] || ''

    if (cn.includes('iotdevices.koiosdigital.net')) {
      // Export public key as SPKI, then re-import with RSA-OAEP for encryption
      const exportedKey = await cert.publicKey.export()
      const spkiBytes = await crypto.subtle.exportKey('spki', exportedKey)

      // Re-import with RSA-OAEP algorithm for encryption
      return await crypto.subtle.importKey(
        'spki',
        spkiBytes,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
      )
    }
  }

  throw new Error('No device certificate found (CN must contain iotdevices.koiosdigital.net)')
}

/**
 * Extract the device CN from a base64-encoded PEM certificate chain.
 * @param pemChain - Base64-encoded PEM certificate chain
 * @returns The CN of the device certificate
 */
export function extractDeviceCn(pemChain: string): string {
  const rawPemChain = Buffer.from(pemChain, 'base64').toString('utf-8')
  const certPems = rawPemChain
    .split(/-----END CERTIFICATE-----/)
    .filter((s) => s.includes('-----BEGIN CERTIFICATE-----'))
    .map((s) => s.trim() + '\n-----END CERTIFICATE-----')

  for (const pem of certPems) {
    const cert = new x509.X509Certificate(pem)
    const cn = cert.subject.match(/CN=([^,]+)/)?.[1] || ''
    if (cn.includes('iotdevices.koiosdigital.net')) {
      return cn
    }
  }

  throw new Error('No device certificate found')
}

// =============================================================================
// License Signing
// =============================================================================

export interface LicensePayload {
  for_device: string
  max_patterns: number
  valid_from: number
  valid_to: number
  license_id: string
  issued_at: number
  store_token: string
}

/**
 * Encode a number as a protobuf varint
 */
function encodeVarint(value: number): Uint8Array {
  const result: number[] = []
  while (value > 127) {
    result.push((value & 0x7f) | 0x80)
    value >>>= 7
  }
  result.push(value)
  return new Uint8Array(result)
}

/**
 * Encode a string field in protobuf format
 */
function encodeString(fieldNum: number, value: string): Uint8Array {
  if (!value) return new Uint8Array(0)
  const encoded = new TextEncoder().encode(value)
  const tag = encodeVarint((fieldNum << 3) | 2) // wire type 2 = length-delimited
  const length = encodeVarint(encoded.length)
  const result = new Uint8Array(tag.length + length.length + encoded.length)
  result.set(tag, 0)
  result.set(length, tag.length)
  result.set(encoded, tag.length + length.length)
  return result
}

/**
 * Encode a uint32 field in protobuf format
 */
function encodeUint32(fieldNum: number, value: number): Uint8Array {
  if (value === 0) return new Uint8Array(0)
  const tag = encodeVarint((fieldNum << 3) | 0) // wire type 0 = varint
  const val = encodeVarint(value)
  const result = new Uint8Array(tag.length + val.length)
  result.set(tag, 0)
  result.set(val, tag.length)
  return result
}

/**
 * Encode an int64 field in protobuf format (as varint for positive values)
 */
function encodeInt64(fieldNum: number, value: number): Uint8Array {
  if (value === 0) return new Uint8Array(0)
  const tag = encodeVarint((fieldNum << 3) | 0) // wire type 0 = varint
  const val = encodeVarint(value)
  const result = new Uint8Array(tag.length + val.length)
  result.set(tag, 0)
  result.set(val, tag.length)
  return result
}

/**
 * Serialize LicensePayload to protobuf bytes.
 *
 * message LicensePayload {
 *   string for_device = 1;
 *   uint32 max_patterns = 2;
 *   int64 valid_from = 3;
 *   int64 valid_to = 4;
 *   string license_id = 5;
 *   int64 issued_at = 6;
 *   string store_token = 7;
 * }
 */
function serializeLicensePayload(payload: LicensePayload): Uint8Array {
  const parts = [
    encodeString(1, payload.for_device),
    encodeUint32(2, payload.max_patterns),
    encodeInt64(3, payload.valid_from),
    encodeInt64(4, payload.valid_to),
    encodeString(5, payload.license_id),
    encodeInt64(6, payload.issued_at),
    encodeString(7, payload.store_token)
  ]

  const totalLength = parts.reduce((sum, p) => sum + p.length, 0)
  const result = new Uint8Array(totalLength)
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.length
  }
  return result
}

export async function signLicense(
  payload: LicensePayload,
  privateKeyPem: string
): Promise<string> {
  // Import RSA private key
  const privateKey = await importRsaPrivateKey(privateKeyPem)

  // Serialize payload to protobuf bytes (must match device's parsing)
  const payloadBytes = serializeLicensePayload(payload)

  // Sign with RSA-SHA256
  const signature = await crypto.subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    privateKey,
    payloadBytes
  )

  // Return base64-encoded signature
  return arrayBufferToBase64(signature)
}

async function importRsaPrivateKey(pem: string): Promise<CryptoKey> {
  // Remove PEM headers and decode
  const pemContents = pem
    .replace(/-----BEGIN (RSA )?PRIVATE KEY-----/, '')
    .replace(/-----END (RSA )?PRIVATE KEY-----/, '')
    .replace(/\s/g, '')

  const binaryDer = base64ToArrayBuffer(pemContents)

  return await crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  )
}

// =============================================================================
// Pattern Format Conversion
// =============================================================================

interface BinaryPoint {
  theta: number // radians
  rho: number // 0.0 to 1.0
}

/**
 * Parse text pattern (theta rho per line) to binary points.
 * Text format: "theta rho\n" where theta is radians and rho is 0.0-1.0
 */
function parseTextPattern(text: string): BinaryPoint[] {
  return text
    .split('\n')
    .filter((line) => line.trim() && !line.startsWith('#'))
    .map((line) => {
      const [theta, rho] = line.trim().split(/\s+/).map(parseFloat)
      return { theta, rho }
    })
    .filter((p) => !isNaN(p.theta) && !isNaN(p.rho))
}

/**
 * Convert pattern points to binary format.
 * Binary format: 6 bytes per point (float32 theta + uint16 rho)
 */
function createBinaryPayload(points: BinaryPoint[]): Uint8Array {
  const buffer = new ArrayBuffer(points.length * 6)
  const view = new DataView(buffer)

  points.forEach((p, i) => {
    const offset = i * 6
    view.setFloat32(offset, p.theta, true) // little-endian
    view.setUint16(offset + 4, Math.round(p.rho * 65535), true) // little-endian
  })

  return new Uint8Array(buffer)
}

/**
 * Convert text pattern to binary format for encryption.
 * @param textData - Pattern text data (theta rho per line)
 * @returns Binary pattern data (6 bytes per point)
 */
export function textPatternToBinary(textData: string): Uint8Array {
  const points = parseTextPattern(textData)
  return createBinaryPayload(points)
}

// =============================================================================
// Pattern Encryption
// =============================================================================

export interface EncryptionResult {
  encryptedData: Uint8Array // AES-CTR ciphertext (no auth tag)
  encryptedKey: Uint8Array // RSA-OAEP encrypted AES key (512 bytes for RSA-4096)
  iv: Uint8Array // 16-byte IV for CTR mode
  originalSize: number
  originalHash: Uint8Array // SHA-256 of plaintext
  pointCount: number // Number of points in pattern
}

export async function encryptPattern(
  patternData: Uint8Array,
  devicePublicKey: CryptoKey
): Promise<EncryptionResult> {
  // Generate random AES-256 key and 16-byte IV for CTR mode
  const aesKey = (await crypto.subtle.generateKey({ name: 'AES-CTR', length: 256 }, true, [
    'encrypt',
  ])) as CryptoKey
  const iv = crypto.getRandomValues(new Uint8Array(16))

  // Calculate original hash (integrity verified on download)
  const originalHash = new Uint8Array(await crypto.subtle.digest('SHA-256', patternData))

  // Encrypt pattern with AES-256-CTR
  const encryptedData = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CTR', counter: iv, length: 64 }, aesKey, patternData)
  )

  // Export AES key for encryption
  const rawAesKey = new Uint8Array((await crypto.subtle.exportKey('raw', aesKey)) as ArrayBuffer)

  // Encrypt AES key with device's RSA public key (OAEP-SHA256)
  const encryptedKey = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, devicePublicKey, rawAesKey)
  )

  // Calculate point count (6 bytes per point: float32 theta + uint16 rho)
  const pointCount = Math.floor(patternData.length / 6)

  return {
    encryptedData,
    encryptedKey,
    iv,
    originalSize: patternData.length,
    originalHash,
    pointCount,
  }
}

// =============================================================================
// Encrypted Pattern File Builder
// =============================================================================

const VERSION = 0x0001
const SCHEME = 1 // RSA-OAEP + AES-CTR
const FLAGS = 0x01 // Binary format
const HEADER_SIZE = 576

export function buildEncryptedPatternFile(result: EncryptionResult): Uint8Array {
  // Validate encrypted key size (512 bytes for RSA-4096)
  if (result.encryptedKey.length !== 512) {
    throw new Error(`Expected 512-byte encrypted key, got ${result.encryptedKey.length}`)
  }

  // Validate IV size (16 bytes for CTR mode)
  if (result.iv.length !== 16) {
    throw new Error(`Expected 16-byte IV, got ${result.iv.length}`)
  }

  // Build header (576 bytes)
  const header = new ArrayBuffer(HEADER_SIZE)
  const view = new DataView(header)
  const bytes = new Uint8Array(header)

  let offset = 0

  // Magic (4 bytes) - "KDEP" as ASCII bytes
  // ESP32 reads as LE uint32, so we write bytes directly: K, D, E, P
  // This gives 0x5045444B when read as LE on ESP32
  bytes[0] = 0x4b // 'K'
  bytes[1] = 0x44 // 'D'
  bytes[2] = 0x45 // 'E'
  bytes[3] = 0x50 // 'P'
  offset += 4

  // Version (2 bytes) - little-endian
  view.setUint16(offset, VERSION, true)
  offset += 2

  // Scheme (1 byte)
  view.setUint8(offset, SCHEME)
  offset += 1

  // Flags (1 byte) - 0x01 = binary format
  view.setUint8(offset, FLAGS)
  offset += 1

  // Original size (4 bytes) - little-endian
  view.setUint32(offset, result.originalSize, true)
  offset += 4

  // Point count (4 bytes) - little-endian
  view.setUint32(offset, result.pointCount, true)
  offset += 4

  // Original hash (32 bytes)
  bytes.set(result.originalHash, offset)
  offset += 32

  // Encrypted key (512 bytes)
  bytes.set(result.encryptedKey, offset)
  offset += 512

  // IV (16 bytes for CTR mode)
  bytes.set(result.iv, offset)
  offset += 16

  // Verify offset matches header size
  if (offset !== HEADER_SIZE) {
    throw new Error(`Header size mismatch: ${offset} != ${HEADER_SIZE}`)
  }

  // Combine header + encrypted data (CTR mode, no auth tag)
  const totalSize = HEADER_SIZE + result.encryptedData.length
  const file = new Uint8Array(totalSize)
  file.set(bytes, 0)
  file.set(result.encryptedData, HEADER_SIZE)

  return file
}

// =============================================================================
// Utility Functions
// =============================================================================

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

export { arrayBufferToBase64, serializeLicensePayload }
