-- Messages from the contact form on the privacy page (removal requests, mistakes in a result, questions).
CREATE TABLE IF NOT EXISTS contact_requests (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  kind       TEXT    NOT NULL,
  message    TEXT    NOT NULL,
  contact    TEXT,
  lang       TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_contact_created ON contact_requests (created_at);
