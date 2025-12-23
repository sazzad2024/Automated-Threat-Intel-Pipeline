-- Adversary Profiler Schema - Diamond Model Implementation

-- Adversaries Table
CREATE TABLE adversaries (
    adversary_id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    aliases TEXT[], -- PostgreSQL specific array type
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE
);

-- Infrastructure Table
CREATE TABLE infrastructure (
    infrastructure_id SERIAL PRIMARY KEY,
    type VARCHAR(50) NOT NULL, -- e.g., 'IP', 'Domain', 'Email'
    value VARCHAR(255) NOT NULL,
    description TEXT,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP WITH TIME ZONE
);

-- Capabilities Table
CREATE TABLE capabilities (
    capability_id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(50), -- e.g., 'Malware', 'Tool', 'Exploit'
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Victims Table
CREATE TABLE victims (
    victim_id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    sector VARCHAR(100),
    region VARCHAR(100),
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- MITRE ATT&CK Mappings Table
CREATE TABLE mitre_attack_mappings (
    mapping_id SERIAL PRIMARY KEY,
    tid VARCHAR(20) NOT NULL UNIQUE, -- e.g., T1001
    technique_name VARCHAR(255) NOT NULL,
    description TEXT
);

-- Central Events Table (Diamond Model Linkage)
CREATE TABLE events (
    event_id SERIAL PRIMARY KEY,
    event_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    description TEXT,
    adversary_id INTEGER REFERENCES adversaries(adversary_id),
    infrastructure_id INTEGER REFERENCES infrastructure(infrastructure_id),
    capability_id INTEGER REFERENCES capabilities(capability_id),
    victim_id INTEGER REFERENCES victims(victim_id),
    mitre_tid VARCHAR(20) REFERENCES mitre_attack_mappings(tid),
    confidence_score FLOAT CHECK (confidence_score >= 0 AND confidence_score <= 1.0)
);

-- Indexes for performance on foreign keys
CREATE INDEX idx_events_adversary ON events(adversary_id);
CREATE INDEX idx_events_infrastructure ON events(infrastructure_id);
CREATE INDEX idx_events_capability ON events(capability_id);
CREATE INDEX idx_events_victim ON events(victim_id);
