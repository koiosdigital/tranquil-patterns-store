import { Hono } from 'hono'
import { type AppEnv, jsonError } from '../app'
import {
  type Pattern,
  type Playlist,
  type PlaylistWithPatterns,
  postPlaylistBodySchema,
  uuidSchema,
  paginationQuerySchema,
} from '../types'
import * as auth from '../auth'

const playlists = new Hono<AppEnv>()

playlists.get('/', auth.authMiddleware(), async (c) => {
  const query = paginationQuerySchema.safeParse({
    page: c.req.query('page'),
    per_page: c.req.query('per_page'),
  })

  const { page, per_page } = query.success ? query.data : { page: 1, per_page: 20 }
  const offset = (page - 1) * per_page

  // Get total count
  const countStmt = c.env.database.prepare('SELECT COUNT(*) as total FROM playlists')
  const countResult = await countStmt.first<{ total: number }>()
  const total = countResult?.total ?? 0

  // Get paginated playlists
  const playlistsStmt = c.env.database
    .prepare('SELECT * FROM playlists ORDER BY name LIMIT ? OFFSET ?')
    .bind(per_page, offset)
  const { results: playlistResults }: { results: Playlist[] } = await playlistsStmt.all()

  // For each playlist, get its patterns via the junction table
  const playlistsWithPatterns: PlaylistWithPatterns[] = await Promise.all(
    playlistResults.map(async (playlist) => {
      const patternsStmt = c.env.database
        .prepare(
          `SELECT p.* FROM patterns p
           INNER JOIN playlist_patterns pp ON p.id = pp.pattern_id
           INNER JOIN playlists pl ON pp.playlist_id = pl.id
           WHERE pl.uuid = ?
           ORDER BY pp.position`
        )
        .bind(playlist.uuid)
      const { results: patterns }: { results: Pattern[] } = await patternsStmt.all()

      return {
        ...playlist,
        patterns,
      }
    })
  )

  return c.json({
    data: playlistsWithPatterns,
    pagination: {
      total,
      page,
      per_page,
      total_pages: Math.ceil(total / per_page),
    },
  })
})

playlists.get('/:uuid', auth.authMiddleware(), async (c) => {
  const uuidResult = uuidSchema.safeParse(c.req.param('uuid'))
  if (!uuidResult.success) {
    return jsonError(c, 400, 'Invalid UUID format')
  }

  // Get the playlist
  const playlistStmt = c.env.database
    .prepare('SELECT * FROM playlists WHERE uuid=?')
    .bind(uuidResult.data)
  const playlist: Playlist | null = await playlistStmt.first()

  if (!playlist) {
    return jsonError(c, 404, 'Playlist not found')
  }

  // Get patterns via junction table
  const patternsStmt = c.env.database
    .prepare(
      `SELECT p.* FROM patterns p
       INNER JOIN playlist_patterns pp ON p.id = pp.pattern_id
       INNER JOIN playlists pl ON pp.playlist_id = pl.id
       WHERE pl.uuid = ?
       ORDER BY pp.position`
    )
    .bind(uuidResult.data)
  const { results: patterns }: { results: Pattern[] } = await patternsStmt.all()

  const playlistWithPatterns: PlaylistWithPatterns = {
    ...playlist,
    patterns,
  }

  c.header('Cache-Control', 'public, max-age=31536000')
  return c.json(playlistWithPatterns)
})

playlists.post('/', auth.authMiddleware(), async (c) => {
  if (!auth.isAdmin(c)) {
    return jsonError(c, 403, 'Admin access required')
  }

  let json: unknown
  try {
    json = await c.req.json()
  } catch {
    return jsonError(c, 400, 'Request body must be valid JSON')
  }

  const bodyResult = postPlaylistBodySchema.safeParse(json)
  if (!bodyResult.success) {
    const message = bodyResult.error.issues[0]?.message ?? 'Invalid request body'
    return jsonError(c, 400, message)
  }

  const playlist = bodyResult.data
  const now = new Date().toISOString()

  // Insert playlist
  const playlistStmt = c.env.database
    .prepare(
      `INSERT INTO playlists (uuid, name, description, featured_pattern_uuid, date, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      playlist.uuid,
      playlist.name,
      playlist.description ?? '',
      playlist.featured_pattern_uuid ?? null,
      playlist.date ?? now,
      now,
      now
    )

  try {
    await playlistStmt.run()
  } catch (e) {
    const message = e instanceof Error ? e.message : 'Database error'
    return jsonError(c, 500, message)
  }

  // Get the newly created playlist's ID
  const getPlaylistStmt = c.env.database
    .prepare('SELECT id FROM playlists WHERE uuid = ?')
    .bind(playlist.uuid)
  const newPlaylist: { id: number } | null = await getPlaylistStmt.first()

  if (!newPlaylist) {
    return jsonError(c, 500, 'Failed to retrieve created playlist')
  }

  // Insert pattern associations into junction table
  if (playlist.pattern_uuids && playlist.pattern_uuids.length > 0) {
    for (let i = 0; i < playlist.pattern_uuids.length; i++) {
      const patternUuid = playlist.pattern_uuids[i]

      // Get pattern ID from UUID
      const patternStmt = c.env.database
        .prepare('SELECT id FROM patterns WHERE uuid = ?')
        .bind(patternUuid)
      const pattern: { id: number } | null = await patternStmt.first()

      if (pattern) {
        const junctionStmt = c.env.database
          .prepare(
            'INSERT INTO playlist_patterns (playlist_id, pattern_id, position) VALUES (?, ?, ?)'
          )
          .bind(newPlaylist.id, pattern.id, i)

        try {
          await junctionStmt.run()
        } catch (e) {
          // Log but continue - pattern might not exist
          console.error(`Failed to add pattern ${patternUuid} to playlist: ${e}`)
        }
      }
    }
  }

  return c.json({ uuid: playlist.uuid })
})

export default playlists
