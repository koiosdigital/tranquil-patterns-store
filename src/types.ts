import { z } from 'zod'

// =============================================================================
// Environment Bindings
// =============================================================================

export type CloudflareBindings = {
  bucket: R2Bucket
  database: D1Database
  audit_kv: KVNamespace // Audit logs and rate limiting
  ADMIN_JWT_SECRET: string
  USER_JWT_SECRET: string
  LICENSE_SIGNING_KEY: string // RSA-2048 private key (PEM) for signing licenses
}

// =============================================================================
// UUID Validation
// =============================================================================

export const uuidSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, 'Invalid UUID format')

// =============================================================================
// Domain Schemas
// =============================================================================

export const patternSchema = z.object({
  id: z.number().int().optional(),
  uuid: uuidSchema,
  name: z.string().trim().min(1, 'Name is required').max(255),
  creator: z.string().trim().max(255).default('Uploaded'),
  date: z.string().trim().nullable().optional(),
  popularity: z.number().int().min(0).default(0),
  reversible: z.number().int().min(0).max(1).default(0),
  start_point: z.number().int().min(0).default(0),
  encrypted: z.number().int().min(0).max(1).default(0),
  size_bytes: z.number().int().min(0).default(0),
  created_at: z.string().trim().nullable().optional(),
  last_played_at: z.string().trim().nullable().optional(),
  downloaded_at: z.string().trim().nullable().optional(),
})

export const playlistSchema = z.object({
  id: z.number().int().optional(),
  uuid: uuidSchema,
  name: z.string().trim().min(1, 'Name is required').max(255),
  description: z.string().trim().max(2000).default(''),
  featured_pattern_uuid: uuidSchema.nullable().optional(),
  date: z.string().trim().nullable().optional(),
  created_at: z.string().trim().nullable().optional(),
  updated_at: z.string().trim().nullable().optional(),
})

// =============================================================================
// Pagination
// =============================================================================

export const paginationQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  per_page: z.coerce.number().int().min(1).max(100).default(20),
})

export type PaginationQuery = z.infer<typeof paginationQuerySchema>

export interface PaginatedResponse<T> {
  data: T[]
  pagination: {
    total: number
    page: number
    per_page: number
    total_pages: number
  }
}

// =============================================================================
// Request Body Schemas
// =============================================================================

export const postPatternBodySchema = z.object({
  patternData: z.string().min(1, 'Pattern data is required'),
  pattern: z.object({
    uuid: uuidSchema,
    name: z.string().trim().min(1, 'Name is required').max(255),
    creator: z.string().trim().max(255).default('Uploaded'),
    date: z.string().trim().nullable().optional(),
    popularity: z.number().int().min(0).default(0),
    reversible: z.number().int().min(0).max(1).default(0),
    start_point: z.number().int().min(0).default(0),
    encrypted: z.number().int().min(0).max(1).default(0),
  }),
  thumbData: z.string().min(1, 'Thumbnail data is required'),
})

export const postPlaylistBodySchema = z.object({
  uuid: uuidSchema,
  name: z.string().trim().min(1, 'Name is required').max(255),
  description: z.string().trim().max(2000).default(''),
  featured_pattern_uuid: uuidSchema.nullable().optional(),
  date: z.string().trim().nullable().optional(),
  pattern_uuids: z.array(uuidSchema).default([]),
})

// =============================================================================
// Inferred Types
// =============================================================================

export type Pattern = z.infer<typeof patternSchema>
export type Playlist = z.infer<typeof playlistSchema>
export type PostPatternBody = z.infer<typeof postPatternBodySchema>
export type PostPlaylistBody = z.infer<typeof postPlaylistBodySchema>

// Playlist with patterns included (for API responses)
export type PlaylistWithPatterns = Playlist & {
  patterns: Pattern[]
}

// =============================================================================
// OpenAPI Specification
// =============================================================================

export const swaggerDocument = {
  openapi: '3.1.0',
  info: {
    title: 'Tranquil Patterns API',
    version: '2.0.0',
    description:
      'API for managing patterns and playlists for Tranquil drawing robots. Authentication is handled via JWT tokens - user tokens for read access, admin tokens for write access.',
  },
  servers: [
    {
      url: 'https://tranquilapi.acvigue.workers.dev',
      description: 'Production',
    },
  ],
  tags: [
    { name: 'Patterns', description: 'Pattern management endpoints' },
    { name: 'Playlists', description: 'Playlist management endpoints' },
    { name: 'License', description: 'Device license management' },
  ],
  paths: {
    '/patterns': {
      get: {
        tags: ['Patterns'],
        summary: 'List all patterns',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            name: 'page',
            in: 'query',
            schema: { type: 'integer', minimum: 1, default: 1 },
            description: 'Page number',
          },
          {
            name: 'per_page',
            in: 'query',
            schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
            description: 'Items per page',
          },
        ],
        responses: {
          '200': {
            description: 'Paginated array of patterns',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PaginatedPatterns' },
              },
            },
          },
          '401': { description: 'Unauthorized' },
        },
      },
      post: {
        tags: ['Patterns'],
        summary: 'Create a new pattern (admin only)',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/PostPatternBody' },
            },
          },
        },
        responses: {
          '200': { description: 'Pattern created' },
          '400': { description: 'Invalid request body' },
          '401': { description: 'Unauthorized' },
          '403': { description: 'Admin access required' },
        },
      },
    },
    '/patterns/{uuid}': {
      get: {
        tags: ['Patterns'],
        summary: 'Get pattern by UUID',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            name: 'uuid',
            in: 'path',
            required: true,
            schema: { type: 'string', format: 'uuid' },
          },
        ],
        responses: {
          '200': {
            description: 'Pattern details',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/Pattern' },
              },
            },
          },
          '400': { description: 'Invalid UUID format' },
          '401': { description: 'Unauthorized' },
          '404': { description: 'Pattern not found' },
        },
      },
    },
    '/patterns/{uuid}/thumb.png': {
      get: {
        tags: ['Patterns'],
        summary: 'Get pattern thumbnail',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            name: 'uuid',
            in: 'path',
            required: true,
            schema: { type: 'string', format: 'uuid' },
          },
        ],
        responses: {
          '200': {
            description: 'Pattern thumbnail',
            content: { 'image/png': {} },
          },
          '400': { description: 'Invalid UUID format' },
          '401': { description: 'Unauthorized' },
          '404': { description: 'Thumbnail not found' },
        },
      },
    },
    '/patterns/{uuid}/encrypted': {
      post: {
        tags: ['Patterns'],
        summary: 'Generate encrypted pattern for device (admin only)',
        description:
          'Encrypts a pattern for a specific device using hybrid RSA-OAEP + AES-GCM encryption. Returns a download URL for the encrypted .dat file.',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            name: 'uuid',
            in: 'path',
            required: true,
            schema: { type: 'string', format: 'uuid' },
          },
        ],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/EncryptedPatternRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'Encrypted pattern generated',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/EncryptedPatternResponse' },
              },
            },
          },
          '400': { description: 'Invalid request or certificate' },
          '401': { description: 'Unauthorized' },
          '403': { description: 'Admin access required' },
          '404': { description: 'Pattern not found' },
        },
      },
    },
    '/patterns/download/{token}': {
      get: {
        tags: ['Patterns'],
        summary: 'Download encrypted pattern file',
        description:
          'Downloads an encrypted pattern .dat file using the token from /patterns/{uuid}/encrypted. Rate limited to 20/min, 100/hr, 200/day per device.',
        parameters: [
          {
            name: 'token',
            in: 'path',
            required: true,
            schema: { type: 'string' },
            description: 'Download token in format {uuid}-{randomHex}',
          },
        ],
        responses: {
          '200': {
            description: 'Encrypted pattern file',
            content: { 'application/octet-stream': {} },
          },
          '400': { description: 'Invalid download token' },
          '404': { description: 'Encrypted pattern not found or expired' },
          '429': {
            description: 'Rate limit exceeded',
            headers: {
              'Retry-After': {
                description: 'Seconds until rate limit resets',
                schema: { type: 'integer' },
              },
            },
          },
        },
      },
    },
    '/license': {
      post: {
        tags: ['License'],
        summary: 'Issue device license (admin only)',
        description: 'Issues a signed license for a device, valid for 1 month with 100 max patterns.',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/LicenseRequest' },
            },
          },
        },
        responses: {
          '200': {
            description: 'License issued',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/LicenseResponse' },
              },
            },
          },
          '400': { description: 'Invalid request body' },
          '401': { description: 'Unauthorized' },
          '403': { description: 'Admin access required' },
        },
      },
    },
    '/playlists': {
      get: {
        tags: ['Playlists'],
        summary: 'List all playlists',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            name: 'page',
            in: 'query',
            schema: { type: 'integer', minimum: 1, default: 1 },
            description: 'Page number',
          },
          {
            name: 'per_page',
            in: 'query',
            schema: { type: 'integer', minimum: 1, maximum: 100, default: 20 },
            description: 'Items per page',
          },
        ],
        responses: {
          '200': {
            description: 'Paginated array of playlists with their patterns',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PaginatedPlaylists' },
              },
            },
          },
          '401': { description: 'Unauthorized' },
        },
      },
      post: {
        tags: ['Playlists'],
        summary: 'Create a new playlist (admin only)',
        security: [{ bearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/PostPlaylistBody' },
            },
          },
        },
        responses: {
          '200': { description: 'Playlist created' },
          '400': { description: 'Invalid request body' },
          '401': { description: 'Unauthorized' },
          '403': { description: 'Admin access required' },
        },
      },
    },
    '/playlists/{uuid}': {
      get: {
        tags: ['Playlists'],
        summary: 'Get playlist by UUID',
        security: [{ bearerAuth: [] }],
        parameters: [
          {
            name: 'uuid',
            in: 'path',
            required: true,
            schema: { type: 'string', format: 'uuid' },
          },
        ],
        responses: {
          '200': {
            description: 'Playlist details with patterns',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/PlaylistWithPatterns' },
              },
            },
          },
          '400': { description: 'Invalid UUID format' },
          '401': { description: 'Unauthorized' },
          '404': { description: 'Playlist not found' },
        },
      },
    },
  },
  components: {
    securitySchemes: {
      bearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'User JWT for read access, Admin JWT for write access',
      },
    },
    schemas: {
      Pattern: {
        type: 'object',
        properties: {
          id: { type: 'integer' },
          uuid: { type: 'string', format: 'uuid' },
          name: { type: 'string' },
          creator: { type: 'string' },
          date: { type: 'string', nullable: true },
          popularity: { type: 'integer' },
          reversible: { type: 'integer', enum: [0, 1] },
          start_point: { type: 'integer' },
          encrypted: { type: 'integer', enum: [0, 1] },
          size_bytes: { type: 'integer' },
          created_at: { type: 'string', nullable: true },
          last_played_at: { type: 'string', nullable: true },
          downloaded_at: { type: 'string', nullable: true },
        },
        required: ['uuid', 'name'],
      },
      Playlist: {
        type: 'object',
        properties: {
          id: { type: 'integer' },
          uuid: { type: 'string', format: 'uuid' },
          name: { type: 'string' },
          description: { type: 'string' },
          featured_pattern_uuid: { type: 'string', format: 'uuid', nullable: true },
          date: { type: 'string', nullable: true },
          created_at: { type: 'string', nullable: true },
          updated_at: { type: 'string', nullable: true },
        },
        required: ['uuid', 'name'],
      },
      PlaylistWithPatterns: {
        allOf: [
          { $ref: '#/components/schemas/Playlist' },
          {
            type: 'object',
            properties: {
              patterns: {
                type: 'array',
                items: { $ref: '#/components/schemas/Pattern' },
              },
            },
            required: ['patterns'],
          },
        ],
      },
      PostPatternBody: {
        type: 'object',
        properties: {
          patternData: { type: 'string' },
          pattern: { $ref: '#/components/schemas/Pattern' },
          thumbData: { type: 'string' },
        },
        required: ['patternData', 'pattern', 'thumbData'],
      },
      PostPlaylistBody: {
        type: 'object',
        properties: {
          uuid: { type: 'string', format: 'uuid' },
          name: { type: 'string' },
          description: { type: 'string' },
          featured_pattern_uuid: { type: 'string', format: 'uuid', nullable: true },
          date: { type: 'string', nullable: true },
          pattern_uuids: { type: 'array', items: { type: 'string', format: 'uuid' } },
        },
        required: ['uuid', 'name'],
      },
      Error: {
        type: 'object',
        properties: {
          error: { type: 'string' },
        },
        required: ['error'],
      },
      LicenseRequest: {
        type: 'object',
        properties: {
          device_id: { type: 'string', description: 'Device certificate CN' },
        },
        required: ['device_id'],
      },
      LicensePayload: {
        type: 'object',
        properties: {
          for_device: { type: 'string' },
          max_patterns: { type: 'integer' },
          valid_from: { type: 'integer', description: 'Unix timestamp' },
          valid_to: { type: 'integer', description: 'Unix timestamp' },
          license_id: { type: 'string' },
          issued_at: { type: 'integer', description: 'Unix timestamp' },
          store_token: { type: 'string', description: 'Device-scoped JWT for store access' },
        },
      },
      LicenseResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean' },
          license: { $ref: '#/components/schemas/LicensePayload' },
          signature: { type: 'string', description: 'Base64 RSA-SHA256 signature' },
          server_timestamp: { type: 'integer' },
        },
      },
      EncryptedPatternRequest: {
        type: 'object',
        properties: {
          pem: { type: 'string', description: 'Base64-encoded device certificate chain (PEM format)' },
        },
        required: ['pem'],
      },
      EncryptedPatternResponse: {
        type: 'object',
        properties: {
          success: { type: 'boolean' },
          download_url: { type: 'string', description: 'URL to download encrypted .dat file' },
          pattern_uuid: { type: 'string', format: 'uuid' },
          encryption: {
            type: 'object',
            properties: {
              original_size: { type: 'integer' },
              original_hash: { type: 'string', description: 'Base64 SHA-256 hash' },
              point_count: { type: 'integer', description: 'Number of points in pattern' },
            },
          },
        },
      },
      Pagination: {
        type: 'object',
        properties: {
          total: { type: 'integer', description: 'Total number of items' },
          page: { type: 'integer', description: 'Current page number' },
          per_page: { type: 'integer', description: 'Items per page' },
          total_pages: { type: 'integer', description: 'Total number of pages' },
        },
        required: ['total', 'page', 'per_page', 'total_pages'],
      },
      PaginatedPatterns: {
        type: 'object',
        properties: {
          data: {
            type: 'array',
            items: { $ref: '#/components/schemas/Pattern' },
          },
          pagination: { $ref: '#/components/schemas/Pagination' },
        },
        required: ['data', 'pagination'],
      },
      PaginatedPlaylists: {
        type: 'object',
        properties: {
          data: {
            type: 'array',
            items: { $ref: '#/components/schemas/PlaylistWithPatterns' },
          },
          pagination: { $ref: '#/components/schemas/Pagination' },
        },
        required: ['data', 'pagination'],
      },
    },
  },
} as const
