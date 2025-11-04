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

CREATE MATERIALIZED VIEW subdomains_all_cleaned_by_etld AS
SELECT
    -- Leftmost subdomain
    subdomain,
    -- Sub-subdomains
    lb.labels_before_etld,
    -- The etld (domain name + .nl)
    parts[array_length(parts,1)-1] || '.' || parts[array_length(parts,1)] AS etld,
    -- Zone size (count of etld), so we can exclude zones of a specific size
    COUNT(*) OVER (PARTITION BY parts[array_length(parts,1)-1] || '.' || parts[array_length(parts,1)]) AS etld_count,
    -- Hashed etld, this will make it easier to group records later
    HASHTEXTEXTENDED(parts[array_length(parts,1)-1] || '.' || parts[array_length(parts,1)], 0) AS etld_hash
FROM subdomains_leftmost_all_by_owner
CROSS JOIN LATERAL string_to_array(TRIM(TRAILING '.' FROM owner), '.') AS parts
CROSS JOIN LATERAL (
  SELECT CASE
           WHEN array_length(parts,1) > 2
           THEN array_to_string(parts[1:array_length(parts,1)-2], '.')
           ELSE NULL
         END AS labels_before_etld
) AS lb
-- Exclude IP addresses broken up by hyphens or dots, this also excludes in-addr-arpa records
WHERE NOT COALESCE(lb.labels_before_etld, '') ~ $$((0*(25[0-5]|2[0-4][0-9]|1[0-9]{2}|0*[0-9]{1,2}))-){3}0*(25[0-5]|2[0-4][0-9]|1[0-9]{2}|0*[0-9]{1,2})$$
AND NOT COALESCE(lb.labels_before_etld, '') ~ $$((0*(25[0-5]|2[0-4][0-9]|1[0-9]{2}|0*[0-9]{1,2}))\.){3}0*(25[0-5]|2[0-4][0-9]|1[0-9]{2}|0*[0-9]{1,2})$$
-- Could do some entropy analysis here, to also exclude base64 encoding, encryption, compression and other random junk.
-- Exclude GUIDs
AND NOT COALESCE(lb.labels_before_etld, '') ~ $$[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$$
-- Exclude hex-encoded 16 character labels.
AND NOT COALESCE(lb.labels_before_etld, '') ~ $$[a-f0-9]{16}$$
-- Exclude alphanumeric 32 character labels
AND NOT COALESCE(lb.labels_before_etld, '') ~ $$[a-z0-9]{32}$$
-- Exclude white/black lies artifacts
AND NOT COALESCE(lb.labels_before_etld, '') LIKE '%\x00%'
-- Enforce total FQDN length (subdomain + etld) ≤ 253 characters (RFC 1035)
AND length(TRIM(TRAILING '.' FROM owner)) <= 253
-- Exclude domains with RFC 1035 uncompliant labels (applied only to labels_before_etld)
-- "The labels must follow the rules for ARPANET host names.
--  They must start with a letter, end with a letter or digit, and have as interior characters only letters, digits, and hyphen.
--  There are also some restrictions on the length. Labels must be 63 characters or less."
AND NOT EXISTS (
    SELECT 1
    FROM unnest(
        CASE
            WHEN array_length(parts,1) > 2
            THEN parts[1:array_length(parts,1)-2]
            ELSE ARRAY[]::text[]
        END
    ) AS p
    WHERE
        lower(p) ~ '[^a-z0-9-]'
        OR p ~ '(^-|-$)'
        OR length(p) > 63
);
