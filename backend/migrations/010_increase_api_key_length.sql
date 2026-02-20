-- Increase api_key column length to accommodate longer API keys
-- The previous limit of 64 characters was too short for the new API key format

ALTER TABLE servers ALTER COLUMN api_key TYPE VARCHAR(255);
