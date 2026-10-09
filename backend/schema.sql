-- =============================================================================
-- PostgreSQL DDL Schema for LLM Security Research Platform
-- =============================================================================

-- 1. Datasets Table
CREATE TABLE IF NOT EXISTS datasets (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    source VARCHAR(255) NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_datasets_id ON datasets (id);
CREATE INDEX IF NOT EXISTS ix_datasets_name ON datasets (name);

-- 2. Records Table
CREATE TABLE IF NOT EXISTS records (
    id VARCHAR(36) PRIMARY KEY,
    dataset_id VARCHAR(36) NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    source_type VARCHAR(32) NOT NULL,         -- 'email', 'webpage', 'pdf'
    content TEXT NOT NULL,
    label VARCHAR(32) NOT NULL,               -- 'benign', 'prompt_injection', 'malicious_file'
    attack_type VARCHAR(64),                  -- 'direct_prompt_injection', 'indirect_prompt_injection', 'pdf_prompt_injection', 'malware', NULL
    file_name VARCHAR(255),
    file_hash VARCHAR(64),                    -- SHA-256 of raw file bytes
    content_hash VARCHAR(64) NOT NULL,        -- SHA-256 of extracted plain content
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Primary and Column Indexes
CREATE INDEX IF NOT EXISTS ix_records_id ON records (id);
CREATE INDEX IF NOT EXISTS ix_records_dataset_id ON records (dataset_id);
CREATE INDEX IF NOT EXISTS ix_records_source_type ON records (source_type);
CREATE INDEX IF NOT EXISTS ix_records_label ON records (label);
CREATE INDEX IF NOT EXISTS ix_records_attack_type ON records (attack_type);
CREATE INDEX IF NOT EXISTS ix_records_file_hash ON records (file_hash);
CREATE INDEX IF NOT EXISTS ix_records_content_hash ON records (content_hash);
CREATE INDEX IF NOT EXISTS ix_records_created_at ON records (created_at);

-- Composite Indexes for High Performance Filtering and Deduplication
CREATE INDEX IF NOT EXISTS ix_records_dataset_filehash ON records (dataset_id, file_hash);
CREATE INDEX IF NOT EXISTS ix_records_dataset_contenthash ON records (dataset_id, content_hash);
CREATE INDEX IF NOT EXISTS ix_records_source_label ON records (source_type, label);
