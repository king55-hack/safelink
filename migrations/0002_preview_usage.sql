-- Daily counter for NEW screenshot previews (each one uses Cloudflare Browser Rendering time).
CREATE TABLE IF NOT EXISTS preview_usage (
  day TEXT PRIMARY KEY,   -- YYYY-MM-DD (UTC)
  n   INTEGER NOT NULL
);
