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
      // Extract the public key
      return await cert.publicKey.export()
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
}

export async function signLicense(
  payload: LicensePayload,
  privateKeyPem: string
): Promise<string> {
  // Import RSA private key
  const privateKey = await importRsaPrivateKey(privateKeyPem)

  // Serialize payload to JSON (deterministic order)
  const payloadJson = JSON.stringify(payload)
  const payloadBytes = new TextEncoder().encode(payloadJson)

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

const MAGIC = 0x4b444550 // "KDEP"
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

  // Magic (4 bytes) - little-endian
  view.setUint32(offset, MAGIC, true)
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

export { arrayBufferToBase64 }
