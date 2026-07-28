-- Create the hash tracking table
CREATE TABLE IF NOT EXISTS vic_hashes (
    id SERIAL PRIMARY KEY,
    hash_type VARCHAR(20) NOT NULL, -- 'SHA256' or 'PHASH'
    hash_value VARCHAR(255) NOT NULL,
    classification VARCHAR(50) NOT NULL,
    case_reference VARCHAR(100) NOT NULL,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index the hash value for lightning-fast exact match lookups
CREATE INDEX idx_vic_hashes_value ON vic_hashes (hash_value);

-- Insert mock threat data for testing the UI and Watchdog
INSERT INTO vic_hashes (hash_type, hash_value, classification, case_reference) VALUES
('SHA256', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'CSAM', 'MOCK_CASE_ALPHA'),
('PHASH', 'e31e3cc38e3c3c3c', 'CSAM', 'MOCK_CASE_BETA');
