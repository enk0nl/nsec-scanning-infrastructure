CREATE TABLE scans (
    id SERIAL PRIMARY KEY,
    start_time TIMESTAMP NOT NULL,
    end_time TIMESTAMP,
    initiated_by VARCHAR(255),
    zone VARCHAR(255) NOT NULL,
    scan_type VARCHAR(50),
    zone_type VARCHAR(50),
    exitcode VARCHAR(10)
);

CREATE TABLE nsec_resource_records (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    owner VARCHAR(255),
    next_owner VARCHAR(255),
    ttl INTEGER,
    class VARCHAR(10),
    types VARCHAR(255),
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE nsec3_resource_records (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    owner VARCHAR(255) NOT NULL,
    hashed_owner VARCHAR(255) NOT NULL,
    next_hashed_owner VARCHAR(255),
    ttl INTEGER,
    class VARCHAR(10),
    types VARCHAR(255),
    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE nsec3_parameters (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
    hash_algorithm INTEGER,
    flags INTEGER,
    iterations INTEGER,
    salt VARCHAR(255)
);

CREATE TABLE logs (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER REFERENCES scans(id) ON DELETE SET NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    message TEXT,
    severity VARCHAR(20) CHECK (severity IN ('INFO', 'WARNING', 'ERROR', 'CRITICAL'))
);

CREATE INDEX idx_nsec_resource_records_scan_id ON nsec_resource_records (scan_id);
CREATE INDEX idx_nsec3_resource_records_scan_id ON nsec3_resource_records (scan_id);
CREATE INDEX idx_nsec3_parameters_scan_id ON nsec3_parameters (scan_id);
CREATE INDEX idx_logs_scan_id ON logs (scan_id);

CREATE MATERIALIZED VIEW domains_all AS SELECT DISTINCT REGEXP_REPLACE(zone, '\.$', '') AS domain FROM scans;
CREATE INDEX idx_domains_all_domain ON domains_all(domain);
CREATE MATERIALIZED VIEW domains_unknown AS SELECT DISTINCT REGEXP_REPLACE(zone, '\.$', '') AS domain FROM scans WHERE zone_type = 'unknown';
CREATE INDEX idx_domains_unknown_domain ON domains_unknown(domain);
CREATE MATERIALIZED VIEW domains_no_dnssec AS SELECT DISTINCT REGEXP_REPLACE(zone, '\.$', '') AS domain FROM scans WHERE zone_type = 'no_dnssec';
CREATE INDEX idx_domains_no_dnssec_domain ON domains_no_dnssec(domain);
CREATE MATERIALIZED VIEW domains_nsec AS SELECT DISTINCT REGEXP_REPLACE(zone, '\.$', '') AS domain FROM scans WHERE zone_type = 'nsec';
CREATE INDEX idx_domains_nsec_domain ON domains_nsec(domain);
CREATE MATERIALIZED VIEW domains_nsec3 AS SELECT DISTINCT REGEXP_REPLACE(zone, '\.$', '') AS domain FROM scans WHERE zone_type = 'nsec3';
CREATE INDEX idx_domains_nsec3_domain ON domains_nsec3(domain);

CREATE MATERIALIZED VIEW domains_nsec_lies AS SELECT DISTINCT REGEXP_REPLACE(zone, '\.$', '') AS domain FROM scans WHERE zone_type = 'nsec' AND id IN (
    SELECT DISTINCT scan_id FROM logs WHERE message LIKE '%nsone.net%' OR message LIKE '%cloudflare.com%' OR message LIKE '%awsdns%');
CREATE INDEX idx_domains_nsec_lies ON domains_nsec_lies(domain);
CREATE MATERIALIZED VIEW domains_nsec3_lies AS SELECT DISTINCT REGEXP_REPLACE(zone, '\.$', '') AS domain FROM scans WHERE zone_type = 'nsec3' AND id IN (
    SELECT DISTINCT scan_id FROM logs WHERE message LIKE '%nsone.net%' OR message LIKE '%cloudflare.com%' OR message LIKE '%awsdns%');
CREATE INDEX idx_domains_nsec3_lies ON domains_nsec3_lies(domain);
CREATE MATERIALIZED VIEW domains_nsec_avoid_lies AS SELECT * FROM domains_nsec WHERE domain NOT IN (SELECT domain from domains_nsec_lies);
CREATE INDEX idx_domains_nsec_avoid_lies ON domains_nsec_avoid_lies(domain);
CREATE MATERIALIZED VIEW domains_nsec3_avoid_lies AS SELECT * FROM domains_nsec3 WHERE domain NOT IN (SELECT domain from domains_nsec3_lies);
CREATE INDEX idx_domains_nsec3_avoid_lies ON domains_nsec3_avoid_lies(domain);

CREATE VIEW stats_total_scans AS SELECT COUNT(id) from scans;
CREATE VIEW stats_total_nsec_scans AS SELECT COUNT(*) FROM scans WHERE scan_type = 'nsec';
CREATE VIEW stats_nsec_zones_walked AS SELECT COUNT(DISTINCT zone) FROM scans WHERE scan_type = 'nsec' OR (scan_type = 'auto' AND 'zone_type' = 'nsec');
CREATE VIEW stats_nsec3_zones_walked AS SELECT COUNT(DISTINCT zone) FROM scans WHERE scan_type = 'nsec3' OR (scan_type = 'auto' AND 'zone_type' = 'nsec3');
CREATE VIEW stats_total_zones_walked AS SELECT COUNT(DISTINCT zone) FROM scans WHERE scan_type = 'nsec' OR scan_type = 'nsec3' OR (scan_type = 'auto' AND ('zone_type' = 'nsec3' OR 'zone_type' = 'nsec'));

CREATE VIEW stats_nsec_zones_largest AS SELECT scans.id AS scan_id,start_time,zone,COUNT(*) FROM scans INNER JOIN nsec_resource_records ON scans.id = nsec_resource_records.scan_id WHERE scan_type = 'nsec' OR (scan_type = 'auto' AND zone_type = 'nsec') GROUP BY zone,scans.id,start_time ORDER BY count DESC LIMIT 50;
CREATE VIEW stats_nsec3_zones_largest AS SELECT scans.id AS scan_id,start_time,zone,COUNT(*) FROM scans INNER JOIN nsec3_resource_records ON scans.id = nsec3_resource_records.scan_id WHERE scan_type = 'nsec3' OR (scan_type = 'auto' AND zone_type = 'nsec3')  GROUP BY zone,scans.id,start_time ORDER BY count DESC LIMIT 50;
CREATE VIEW stats_nsec_zones_most_logs AS SELECT scans.id AS scan_id,start_time,zone,COUNT(*) FROM scans INNER JOIN logs ON scans.id = logs.scan_id WHERE scan_type = 'nsec'  OR (scan_type = 'auto' AND zone_type = 'nsec') GROUP BY zone,scans.id,start_time ORDER BY count DESC LIMIT 50;
CREATE VIEW stats_nsec3_zones_most_logs AS SELECT scans.id AS scan_id,start_time,zone,COUNT(*) FROM scans INNER JOIN logs ON scans.id = logs.scan_id WHERE scan_type = 'nsec3'  OR (scan_type = 'auto' AND zone_type = 'nsec3') GROUP BY zone,scans.id,start_time ORDER BY count DESC LIMIT 50;

CREATE VIEW stats_total_scans_by_zone_type AS SELECT zone_type,COUNT(id) FROM scans
    GROUP BY zone_type
    ORDER BY
        CASE zone_type
            WHEN 'nsec3' THEN 1
            WHEN 'nsec' THEN 2
            WHEN 'no_dnssec' THEN 3
            WHEN 'unknown' THEN 4
            ELSE 5
        END;

CREATE VIEW stats_total_domains AS SELECT COUNT(DISTINCT zone) FROM scans;

CREATE VIEW stats_domains_by_zone_type AS
    WITH ranked_domains AS (
        SELECT
            zone,
            zone_type,
            ROW_NUMBER() OVER (
                PARTITION BY zone
                ORDER BY
                    CASE zone_type
                        WHEN 'nsec3' THEN 1
                        WHEN 'nsec' THEN 2
                        WHEN 'no_dnssec' THEN 3
                        WHEN 'unknown' THEN 4
                        ELSE 5
                    END
            ) AS rn
        FROM scans
    ),
    highest_precedence AS (
        SELECT zone, zone_type
        FROM ranked_domains
        WHERE rn = 1
    )
    SELECT zone_type, COUNT(*)
    FROM highest_precedence
    GROUP BY zone_type
    ORDER BY
        CASE zone_type
            WHEN 'nsec3' THEN 1
            WHEN 'nsec' THEN 2
            WHEN 'no_dnssec' THEN 3
            WHEN 'unknown' THEN 4
            ELSE 5
        END;

CREATE MATERIALIZED VIEW subdomains_all_by_owner AS SELECT
    d.owner,
    subs[i] AS subdomain
FROM (
    SELECT DISTINCT owner
    FROM nsec_resource_records
) d
CROSS JOIN LATERAL (
    SELECT string_to_array(d.owner, '.') AS full_parts
) p
CROSS JOIN LATERAL (
    SELECT p.full_parts[1:array_length(p.full_parts, 1) - 3] AS subs
) sliced
CROSS JOIN LATERAL generate_subscripts(sliced.subs, 1) AS gs(i);

CREATE MATERIALIZED VIEW subdomains_a_aaaa_by_owner AS SELECT
    d.owner,
    subs[i] AS subdomain
FROM (
    SELECT DISTINCT owner
    FROM nsec_resource_records
    WHERE (
        types LIKE '{A%'
        OR types LIKE '%,A%'
        OR types LIKE '{AAAA%'
        OR types LIKE '%,AAAA%'
    )
) d
CROSS JOIN LATERAL (
    SELECT string_to_array(d.owner, '.') AS full_parts
) p
CROSS JOIN LATERAL (
    SELECT p.full_parts[1:array_length(p.full_parts, 1) - 3] AS subs
) sliced
CROSS JOIN LATERAL generate_subscripts(sliced.subs, 1) AS gs(i);

CREATE MATERIALIZED VIEW subdomains_a_aaaa_cname_by_owner AS SELECT
    d.owner,
    subs[i] AS subdomain
FROM (
    SELECT DISTINCT owner
    FROM nsec_resource_records
    WHERE (
        types LIKE '{A%'
        OR types LIKE '%,A%'
        OR types LIKE '{AAAA%'
        OR types LIKE '%,AAAA%'
        OR types LIKE '{CNAME%'
        OR types LIKE '%,CNAME%'
    )
) d
CROSS JOIN LATERAL (
    SELECT string_to_array(d.owner, '.') AS full_parts
) p
CROSS JOIN LATERAL (
    SELECT p.full_parts[1:array_length(p.full_parts, 1) - 3] AS subs
) sliced
CROSS JOIN LATERAL generate_subscripts(sliced.subs, 1) AS gs(i);

CREATE VIEW subdomains_all_by_occurrance AS
SELECT
    subdomain,
    COUNT(*)
FROM subdomains_all_by_owner
GROUP BY subdomain
ORDER BY count DESC, subdomain;

CREATE VIEW subdomains_a_aaaa_by_occurrance AS
SELECT
    subdomain,
    COUNT(*)
FROM subdomains_a_aaaa_by_owner
GROUP BY subdomain
ORDER BY count DESC, subdomain;

CREATE VIEW subdomains_a_aaaa_cname_by_occurrance AS
SELECT
    subdomain,
    COUNT(*)
FROM subdomains_a_aaaa_cname_by_owner
GROUP BY subdomain
ORDER BY count DESC, subdomain;

CREATE MATERIALIZED VIEW subdomains_leftmost_all_by_owner AS
SELECT DISTINCT
    n.owner,
    parts[1] AS subdomain
FROM nsec_resource_records n,
LATERAL string_to_array(n.owner, '.') AS parts
WHERE array_length(parts, 1) >= 4
AND n.owner IS NOT NULL;

CREATE MATERIALIZED VIEW subdomains_leftmost_a_aaaa_by_owner AS
SELECT DISTINCT
    n.owner,
    parts[1] AS subdomain
FROM nsec_resource_records n,
LATERAL string_to_array(n.owner, '.') AS parts
    WHERE (
        n.types LIKE '{A%'
        OR n.types LIKE '%,A%'
        OR n.types LIKE '{AAAA%'
        OR n.types LIKE '%,AAAA%'
    )
AND array_length(parts, 1) >= 4
AND n.owner IS NOT NULL;

CREATE MATERIALIZED VIEW subdomains_leftmost_a_aaaa_cname_by_owner AS
SELECT DISTINCT
    n.owner,
    parts[1] AS subdomain
FROM nsec_resource_records n,
LATERAL string_to_array(n.owner, '.') AS parts
    WHERE (
	types LIKE '{A%'
	OR types LIKE '%,A%'
	OR types LIKE '{AAAA%'
	OR types LIKE '%,AAAA%'
	OR types LIKE '{CNAME%'
	OR types LIKE '%,CNAME%'
    )
AND array_length(parts, 1) >= 4
AND n.owner IS NOT NULL;

CREATE VIEW subdomains_leftmost_all_by_occurrance AS
SELECT
    subdomain,
    COUNT(*)
FROM subdomains_leftmost_all_by_owner
GROUP BY subdomain
ORDER BY count DESC, subdomain;

CREATE VIEW subdomains_leftmost_a_aaaa_by_occurrance AS
SELECT
    subdomain,
    COUNT(*)
FROM subdomains_leftmost_a_aaaa_by_owner
GROUP BY subdomain
ORDER BY count DESC, subdomain;

CREATE VIEW subdomains_leftmost_a_aaaa_cname_by_occurrance AS
SELECT
    subdomain,
    COUNT(*)
FROM subdomains_leftmost_a_aaaa_cname_by_owner
GROUP BY subdomain
ORDER BY count DESC, subdomain;

CREATE VIEW stats_total_owners AS SELECT COUNT(DISTINCT OWNER) FROM nsec_resource_records;
CREATE VIEW stats_total_subdomains AS SELECT COUNT(*) FROM subdomains_all_by_occurrance;

CREATE MATERIALIZED VIEW nameservers_black_lies AS
SELECT DISTINCT
    TRIM(
        TRAILING '.' FROM
        SUBSTRING(message FROM '\(([^\s)]+(?:\.[^\s)]+)+)')
    ) AS nameserver
FROM logs
WHERE message LIKE '%nameserver:%'
    AND scan_id IN (
        SELECT DISTINCT scan_id
        FROM logs
        WHERE message LIKE '%black lies%'
    );

CREATE MATERIALIZED VIEW subdomains_leftmost_cleaned_by_etld AS
SELECT
    -- Leftmost subdomain label (already provided by source view)
    subdomain,
    -- Labels before the eTLD (excluding the eTLD itself)
    CASE WHEN array_length(parts,1) > 2 THEN array_to_string(parts[1:array_length(parts,1)-2], '.') ELSE NULL END AS labels_before_etld,
    -- The eTLD (domain name + .nl)
    parts[array_length(parts,1)-1] || '.' || parts[array_length(parts,1)] AS etld,
    -- Zone size (count of etld), so we can exclude zones of a specific size
    COUNT(*) OVER (PARTITION BY parts[array_length(parts,1)-1] || '.' || parts[array_length(parts,1)]) AS etld_count,
    -- Hashed etld, this will make it easier to group records later
    hashtextextended(parts[array_length(parts,1)-1] || '.' || parts[array_length(parts,1)],0) AS etld_hash
FROM subdomains_leftmost_all_by_owner
CROSS JOIN LATERAL string_to_array(TRIM(TRAILING '.' FROM owner), '.') AS parts
WHERE
    -- Enforce total FQDN length (subdomain + etld) ≤ 253 characters (RFC 1035)
    length(TRIM(TRAILING '.' FROM owner)) <= 253
    -- Apply all exclusions to *only* the leftmost label
    AND (
        -- Exclude IP addresses broken up by hyphens
        subdomain !~ $$((0*(25[0-5]|2[0-4][0-9]|1[0-9]{2}|0*[0-9]{1,2}))-){3}0*(25[0-5]|2[0-4][0-9]|1[0-9]{2}|0*[0-9]{1,2})$$
        -- Could do some entropy analysis here, to also exclude base64 encoding, encryption, compression and other random junk.
        -- Exclude GUIDs
        AND subdomain !~ $$[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$$
        -- Exclude hex-encoded 16 character labels
        AND subdomain !~ $$[a-f0-9]{16}$$
        -- Exclude alphanumeric 32 character labels
        AND subdomain !~ $$[a-z0-9]{32}$$
        -- Exclude white/black lies artifacts
        AND subdomain NOT LIKE '%\x00%'
        -- Exclude subdomains with RFC 1035 uncompliant labels
        -- "The labels must follow the rules for ARPANET host names.
        --  They must start with a letter, end with a letter or digit, and have as interior characters only letters, digits, and hyphen.
        --  There are also some restrictions on the length. Labels must be 63 characters or less."
        AND lower(subdomain) ~ $re$^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$$re$
    );

CREATE VIEW stats_leftmost_removed_by_cleaning AS 
WITH classified AS (
    SELECT
        subdomain,
        CASE
            -- 1. IP-like (hyphen separated)
            WHEN subdomain ~ $$((0*(25[0-5]|2[0-4][0-9]|1[0-9]{2}|0*[0-9]{1,2}))-){3}0*(25[0-5]|2[0-4][0-9]|1[0-9]{2}|0*[0-9]{1,2})$$ THEN 1
            -- 2. GUID (UUID-like)
            WHEN subdomain ~ $$[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$$ THEN 2
            -- 3. Hex-encoded 16-char
            WHEN subdomain ~ $$[a-f0-9]{16}$$ THEN 3
            -- 4. Alphanumeric 32-char
            WHEN subdomain ~ $$[a-z0-9]{32}$$ THEN 4
            -- 5. Null-byte artifacts
            WHEN subdomain LIKE '%\x00%' THEN 5
            -- 6. RFC1035 invalid
            WHEN lower(subdomain) !~ $re$^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$$re$ THEN 6
            ELSE NULL
        END AS stage
    FROM subdomains_leftmost_all_by_owner
),
counts AS (
    SELECT
        stage,
        COUNT(*) AS matched
    FROM classified
    WHERE stage IS NOT NULL
    GROUP BY stage
),
total AS (
    SELECT COUNT(*)::numeric AS total_count FROM subdomains_leftmost_all_by_owner
),
ordered AS (
    SELECT
        stage,
        CASE stage
            WHEN 1 THEN 'IP-like (hyphen)'
            WHEN 2 THEN 'GUID (UUID-like)'
            WHEN 3 THEN 'Hex 16-char'
            WHEN 4 THEN 'Alnum 32-char'
            WHEN 5 THEN 'Null-byte artifacts'
            WHEN 6 THEN 'RFC1035 invalid'
        END AS exclusion,
        matched
    FROM counts
)
SELECT
    stage,
    exclusion,
    matched,
    ROUND(matched * 100.0 / t.total_count, 3) AS pct_of_total,
    SUM(matched) OVER (ORDER BY stage) AS cumulative
FROM ordered, total t
ORDER BY stage;

CREATE VIEW stats_leftmost_removed_by_zonesize_cutoff AS 
WITH total AS (
  SELECT COUNT(*)::numeric AS total_subdomains
  FROM subdomains_leftmost_cleaned_by_etld
),
thresholds AS (
  SELECT *
  FROM (VALUES
    (NULL::int, 'All (no cap)', 'Baseline'),
    (10000, '10,000', 'Minimal'),
    (5000,  '5,000',  'Light'),
    (2500,  '2,500',  'Moderate'),
    (1000,  '1,000',  'Strict'),
    (500,   '500',    'Aggressive')
  ) AS t(threshold, threshold_label, level)
),
exclusions AS (
  SELECT
    t.threshold,
    t.threshold_label,
    t.level,
    COUNT(DISTINCT s.etld) FILTER (WHERE s.etld_count > t.threshold) AS domains_excluded,
    COUNT(*) FILTER (WHERE s.etld_count > t.threshold) AS subdomains_excluded,
    ROUND(
      COUNT(*) FILTER (WHERE s.etld_count > t.threshold) * 100.0 /
      (SELECT total_subdomains FROM total),
      3
    ) AS pct_excluded
  FROM thresholds t
  CROSS JOIN subdomains_leftmost_cleaned_by_etld s
  GROUP BY t.threshold, t.threshold_label, t.level
)
SELECT
  threshold_label AS "Threshold",
  domains_excluded AS "Domains excluded",
  subdomains_excluded AS "Subdomains excluded",
  pct_excluded || '%' AS "% of dataset",
  level AS "Level"
FROM exclusions
ORDER BY
  CASE
    WHEN threshold IS NULL THEN 0
    ELSE threshold
  END DESC NULLS LAST;

