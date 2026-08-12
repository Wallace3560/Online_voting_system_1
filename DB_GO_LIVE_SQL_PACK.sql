-- Online Voting System: Go-Live SQL Pack
-- Database: online_voting_system
-- Run this script in phpMyAdmin SQL tab.
-- Update only the two schedule values below before running.

SET @schedule_start = '2026-08-20 08:00:00';
SET @schedule_end   = '2026-08-27 17:00:00';

-- 1) Schedule sanity check
SELECT
  @schedule_start AS schedule_start,
  @schedule_end AS schedule_end,
  IF(
    STR_TO_DATE(@schedule_end, '%Y-%m-%d %H:%i:%s') > STR_TO_DATE(@schedule_start, '%Y-%m-%d %H:%i:%s'),
    'OK',
    'ERROR: schedule_end must be later than schedule_start'
  ) AS schedule_validation;

-- 2) Apply election schedule and force results hidden before voting starts
INSERT INTO election_settings (setting_key, setting_value)
VALUES
  ('election_start_at', @schedule_start),
  ('election_end_at', @schedule_end),
  ('election_status', 'scheduled'),
  ('results_published', '0')
ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value);

-- 3) Quick status snapshot after applying settings
SELECT setting_key, setting_value
FROM election_settings
WHERE setting_key IN ('election_start_at','election_end_at','election_status','results_published')
ORDER BY setting_key;

-- 4) Readiness summary counters
SELECT 'verified_active_voters' AS item, COUNT(*) AS value
FROM voters
WHERE status = 'active' AND verification_status = 'verified'
UNION ALL
SELECT 'pending_email_verification_voters', COUNT(*)
FROM voters
WHERE status = 'active' AND email_verified = 0
UNION ALL
SELECT 'active_admins', COUNT(*)
FROM admins
WHERE status = 'active'
UNION ALL
SELECT 'active_positions', COUNT(*)
FROM positions
WHERE status = 'active'
UNION ALL
SELECT 'active_candidates', COUNT(*)
FROM candidates
WHERE status = 'active'
UNION ALL
SELECT 'positions_without_candidates', COUNT(*)
FROM positions p
WHERE p.status = 'active'
  AND NOT EXISTS (
    SELECT 1 FROM candidates c
    WHERE c.position_id = p.position_id AND c.status = 'active'
  )
UNION ALL
SELECT 'active_by_elections', COUNT(*)
FROM by_elections
WHERE status = 'active'
UNION ALL
SELECT 'active_by_elections_without_candidates', COUNT(*)
FROM by_elections b
WHERE b.status = 'active'
  AND NOT EXISTS (
    SELECT 1 FROM by_election_candidates c
    WHERE c.by_election_id = b.by_election_id AND c.status = 'active'
  );

-- 5) Candidate coverage per position (must be > 0 for every active position)
SELECT
  p.position_id,
  p.position_name,
  p.scope,
  COUNT(c.candidate_id) AS active_candidates
FROM positions p
LEFT JOIN candidates c
  ON c.position_id = p.position_id
 AND c.status = 'active'
WHERE p.status = 'active'
GROUP BY p.position_id, p.position_name, p.scope
ORDER BY p.display_order, p.position_id;

-- 6) Data integrity checks (all should be 0)
SELECT 'orphan_candidates_position' AS check_name, COUNT(*) AS value
FROM candidates c
LEFT JOIN positions p ON p.position_id = c.position_id
WHERE c.status = 'active' AND p.position_id IS NULL
UNION ALL
SELECT 'orphan_votes_candidate', COUNT(*)
FROM votes v
LEFT JOIN candidates c ON c.candidate_id = v.candidate_id
WHERE c.candidate_id IS NULL
UNION ALL
SELECT 'orphan_votes_position', COUNT(*)
FROM votes v
LEFT JOIN positions p ON p.position_id = v.position_id
WHERE p.position_id IS NULL
UNION ALL
SELECT 'orphan_constituency_county', COUNT(*)
FROM constituencies cs
LEFT JOIN counties co ON co.county_id = cs.county_id
WHERE co.county_id IS NULL
UNION ALL
SELECT 'orphan_ward_constituency', COUNT(*)
FROM wards w
LEFT JOIN constituencies cs ON cs.constituency_id = w.constituency_id
WHERE cs.constituency_id IS NULL;

-- 7) Go/No-Go signal
SELECT
  CASE
    WHEN EXISTS (
      SELECT 1
      FROM positions p
      WHERE p.status = 'active'
        AND NOT EXISTS (
          SELECT 1 FROM candidates c
          WHERE c.position_id = p.position_id AND c.status = 'active'
        )
    ) THEN 'NO-GO: add candidates for all active positions'
    WHEN (SELECT COUNT(*) FROM voters WHERE status='active' AND verification_status='verified') = 0 THEN 'NO-GO: no verified active voters'
    WHEN (SELECT setting_value FROM election_settings WHERE setting_key='results_published' LIMIT 1) = '1' THEN 'NO-GO: results are currently published'
    ELSE 'GO-LIVE READY (database checks passed)'
  END AS go_live_decision;
