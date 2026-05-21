-- Distinguishes which threat campaign a submission was scanned for.
-- Default 'axios' keeps existing submissions and back-compat scanners working unchanged.
ALTER TABLE submissions ADD COLUMN campaign TEXT NOT NULL DEFAULT 'axios';
CREATE INDEX IF NOT EXISTS idx_submissions_campaign ON submissions(campaign);
CREATE INDEX IF NOT EXISTS idx_submissions_campaign_submitted
  ON submissions(campaign, submitted_at DESC);
