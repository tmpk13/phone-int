-- Every column is NOT NULL: D1 hands a SQL NULL over as a JS null, and the
-- rows are deserialized into plain Rust integers and strings.

-- AUTOINCREMENT keeps ids rising after a clear, so a client polling with
-- `after=<last id>` never misses messages that reuse old ids.
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,                  -- 'claude' or 'phone'
    reply_to INTEGER NOT NULL DEFAULT 0,
    body TEXT NOT NULL DEFAULT '',
    choices TEXT NOT NULL DEFAULT '[]',    -- JSON array of strings
    want TEXT NOT NULL DEFAULT 'text',
    files TEXT NOT NULL DEFAULT '[]',      -- JSON array of FileRef
    created INTEGER NOT NULL,              -- unix ms
    answer INTEGER NOT NULL DEFAULT 0,     -- latest reply id
    closed INTEGER NOT NULL DEFAULT 0
);

-- Bodies live in R2 under f/<id>.
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mime TEXT NOT NULL,
    size INTEGER NOT NULL,
    created INTEGER NOT NULL
);

-- Phone tokens, stored as sha256 hex.
CREATE TABLE IF NOT EXISTS devices (
    token_hash TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);

-- The single pairing gate row (see proto::gate).
CREATE TABLE IF NOT EXISTS pairing (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    ver INTEGER NOT NULL,
    last_step INTEGER NOT NULL,
    fails INTEGER NOT NULL,
    window_start INTEGER NOT NULL,
    total_fails INTEGER NOT NULL
);
INSERT OR IGNORE INTO pairing VALUES (1, 0, 0, 0, 0, 0);
