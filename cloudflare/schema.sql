CREATE TABLE IF NOT EXISTS submissions (
    id               TEXT PRIMARY KEY,
    hostname         TEXT NOT NULL,
    username         TEXT NOT NULL,
    submitted_at     TEXT NOT NULL,
    scan_timestamp   TEXT NOT NULL,
    duration         TEXT,
    verdict          TEXT NOT NULL,
    projects_scanned INTEGER,
    vulnerable_count INTEGER,
    critical_count   INTEGER,
    paths_scanned    TEXT,
    campaign         TEXT NOT NULL DEFAULT 'axios',
    brief_key        TEXT NOT NULL,
    report_key       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_submissions_campaign ON submissions(campaign);
CREATE INDEX IF NOT EXISTS idx_submissions_campaign_submitted
  ON submissions(campaign, submitted_at DESC);
