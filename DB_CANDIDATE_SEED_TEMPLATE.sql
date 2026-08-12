-- Online Voting System: Candidate Seed Template
-- Database: online_voting_system
-- Purpose: quickly add candidates for all active positions.
--
-- How to use:
-- 1) Replace placeholder names/parties and IDs.
-- 2) Keep county_id/constituency_id/ward_id NULL for national positions.
-- 3) For county scope, set county_id and keep constituency_id/ward_id NULL.
-- 4) For constituency scope, set constituency_id and keep county_id/ward_id NULL.
-- 5) For ward scope, set ward_id and keep county_id/constituency_id NULL.
-- 6) candidate_photo can be NULL, or set a path like assets/uploads/candidates/your_file.jpg

-- Reference helper queries
SELECT position_id, position_name, scope, status
FROM positions
ORDER BY display_order, position_id;

SELECT county_id, county_name FROM counties ORDER BY county_name;
SELECT constituency_id, county_id, constituency_name FROM constituencies ORDER BY constituency_name;
SELECT ward_id, constituency_id, ward_name FROM wards ORDER BY ward_name;

-- Candidate inserts
INSERT INTO candidates
(position_id, full_name, party_name, candidate_photo, county_id, constituency_id, ward_id, status)
VALUES
-- President (national)
(1, 'Candidate A President', 'Party Alpha', NULL, NULL, NULL, NULL, 'active'),
(1, 'Candidate B President', 'Party Beta', NULL, NULL, NULL, NULL, 'active'),

-- Governor (county) - set county_id
(2, 'Candidate A Governor', 'Party Alpha', NULL, 1, NULL, NULL, 'active'),
(2, 'Candidate B Governor', 'Party Beta', NULL, 1, NULL, NULL, 'active'),

-- Senator (county) - set county_id
(3, 'Candidate A Senator', 'Party Alpha', NULL, 1, NULL, NULL, 'active'),
(3, 'Candidate B Senator', 'Party Beta', NULL, 1, NULL, NULL, 'active'),

-- Woman Representative (county) - set county_id
(4, 'Candidate A Woman Rep', 'Party Alpha', NULL, 1, NULL, NULL, 'active'),
(4, 'Candidate B Woman Rep', 'Party Beta', NULL, 1, NULL, NULL, 'active'),

-- Member of National Assembly (constituency) - set constituency_id
(5, 'Candidate A MNA', 'Party Alpha', NULL, NULL, 1, NULL, 'active'),
(5, 'Candidate B MNA', 'Party Beta', NULL, NULL, 1, NULL, 'active'),

-- Member of County Assembly (ward) - set ward_id
(6, 'Candidate A MCA', 'Party Alpha', NULL, NULL, NULL, 1, 'active'),
(6, 'Candidate B MCA', 'Party Beta', NULL, NULL, NULL, 1, 'active');

-- Verification: candidate coverage by position
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
