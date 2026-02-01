import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { type AppEnv, jsonError } from './app'
import { swaggerDocument } from './types'
import patterns from './routes/patterns'
import playlists from './routes/playlists'
import license from './routes/license'

const app = new Hono<AppEnv>()

// Middleware
app.use(
  '*',
  cors({
    origin: '*',
    allowHeaders: ['Authorization', 'Content-Type'],
    allowMethods: ['GET', 'POST', 'OPTIONS'],
  })
)

// Global error handler
app.onError((err, c) => {
  console.error(err)
  return jsonError(c, 500, 'An unexpected error occurred')
})

// OpenAPI spec
app.get('/swagger.json', (c) => {
  c.header('Cache-Control', 'no-store')
  return c.json(swaggerDocument)
})

// Mount routes
app.route('/patterns', patterns)
app.route('/playlists', playlists)
app.route('/license', license)

// 404 handler
app.notFound((c) => {
  return c.redirect('/swagger.json', 302)
})

export default app
