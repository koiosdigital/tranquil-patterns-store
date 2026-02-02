-- Tranquil Patterns Store Schema
-- Migration: 0001_init

-- Patterns table
CREATE TABLE IF NOT EXISTS patterns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  creator TEXT DEFAULT 'Uploaded',
  date TEXT,
  popularity INTEGER DEFAULT 0,
  reversible INTEGER DEFAULT 0 CHECK (reversible IN (0, 1)),
  start_point INTEGER DEFAULT 0,
  encrypted INTEGER DEFAULT 0 CHECK (encrypted IN (0, 1)),
  size_bytes INTEGER DEFAULT 0,
  created_at TEXT,
  last_played_at TEXT,
  downloaded_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_patterns_uuid ON patterns(uuid);
CREATE INDEX IF NOT EXISTS idx_patterns_popularity ON patterns(popularity DESC);

-- Playlists table
CREATE TABLE IF NOT EXISTS playlists (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT DEFAULT '',
  featured_pattern_uuid TEXT,
  date TEXT,
  created_at TEXT,
  updated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_playlists_uuid ON playlists(uuid);

-- Junction table for playlist-pattern relationships
CREATE TABLE IF NOT EXISTS playlist_patterns (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  playlist_id INTEGER NOT NULL,
  pattern_id INTEGER NOT NULL,
  position INTEGER DEFAULT 0,
  FOREIGN KEY (playlist_id) REFERENCES playlists(id) ON DELETE CASCADE,
  FOREIGN KEY (pattern_id) REFERENCES patterns(id) ON DELETE CASCADE,
  UNIQUE(playlist_id, pattern_id)
);

CREATE INDEX IF NOT EXISTS idx_playlist_patterns_playlist ON playlist_patterns(playlist_id);
CREATE INDEX IF NOT EXISTS idx_playlist_patterns_pattern ON playlist_patterns(pattern_id);
