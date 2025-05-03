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
