-- Community scam reports.
-- We never store IP addresses or the part of a link after "?" / "#".
-- "reporter" is a one-way salted hash (IP + month) used only so one person counts once per site.
CREATE TABLE IF NOT EXISTS reports (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  host       TEXT    NOT NULL,
  url        TEXT    NOT NULL,
  category   TEXT    NOT NULL,
  note       TEXT,
  lang       TEXT,
  reporter   TEXT    NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_host_reporter ON reports (host, reporter);
CREATE INDEX IF NOT EXISTS idx_reports_host ON reports (host);
