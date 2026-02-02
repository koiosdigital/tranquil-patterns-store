import * as x509 from '@peculiar/x509'

// =============================================================================
// Certificate Chain Parsing
// =============================================================================

export async function extractDevicePublicKey(pemChain: string): Promise<CryptoKey> {
  //pemchain is base64
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
// Pattern Encryption
// =============================================================================

export interface EncryptionResult {
  encryptedData: Uint8Array // Ciphertext + GCM tag
  encryptedKey: Uint8Array // RSA-OAEP encrypted AES key (512 bytes for RSA-4096)
  iv: Uint8Array // 12-byte nonce
  originalSize: number
  originalHash: Uint8Array // SHA-256 of plaintext
}

export async function encryptPattern(
  patternData: Uint8Array,
  devicePublicKey: CryptoKey
): Promise<EncryptionResult> {
  // Generate random AES-256 key and IV
  const aesKey = (await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
  ])) as CryptoKey
  const iv = crypto.getRandomValues(new Uint8Array(12))

  // Calculate original hash
  const originalHash = new Uint8Array(await crypto.subtle.digest('SHA-256', patternData))

  // Encrypt pattern with AES-256-GCM
  const encryptedData = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, patternData)
  )

  // Export AES key for encryption
  const rawAesKey = new Uint8Array((await crypto.subtle.exportKey('raw', aesKey)) as ArrayBuffer)

  // Encrypt AES key with device's RSA public key (OAEP-SHA256)
  const encryptedKey = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, devicePublicKey, rawAesKey)
  )

  return {
    encryptedData,
    encryptedKey,
    iv,
    originalSize: patternData.length,
    originalHash,
  }
}

// =============================================================================
// Encrypted Pattern File Builder
// =============================================================================

const VERSION = 0x0001
const SCHEME = 1 // RSA-OAEP + AES-GCM
const HEADER_SIZE = 568

export function buildEncryptedPatternFile(result: EncryptionResult): Uint8Array {
  // Validate encrypted key size (512 bytes for RSA-4096)
  if (result.encryptedKey.length !== 512) {
    throw new Error(`Expected 512-byte encrypted key, got ${result.encryptedKey.length}`)
  }

  // Validate IV size
  if (result.iv.length !== 12) {
    throw new Error(`Expected 12-byte IV, got ${result.iv.length}`)
  }

  // Build header (568 bytes)
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

  // Reserved (1 byte)
  view.setUint8(offset, 0)
  offset += 1

  // Original size (4 bytes) - little-endian
  view.setUint32(offset, result.originalSize, true)
  offset += 4

  // Original hash (32 bytes)
  bytes.set(result.originalHash, offset)
  offset += 32

  // Encrypted key (512 bytes)
  bytes.set(result.encryptedKey, offset)
  offset += 512

  // IV (12 bytes)
  bytes.set(result.iv, offset)
  offset += 12

  // Verify offset matches header size
  if (offset !== HEADER_SIZE) {
    throw new Error(`Header size mismatch: ${offset} != ${HEADER_SIZE}`)
  }

  // Combine header + encrypted data (includes GCM tag at end)
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
