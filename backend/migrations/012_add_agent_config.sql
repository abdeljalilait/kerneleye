-- Add agent configuration table and related fields

-- Table to store agent configurations
CREATE TABLE IF NOT EXISTS agent_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    mode VARCHAR(50) NOT NULL DEFAULT 'block_hybrid',
    features JSONB NOT NULL DEFAULT '{}',
    threshold INTEGER NOT NULL DEFAULT 80,
    duration VARCHAR(10) NOT NULL DEFAULT '1h',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(server_id)
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_agent_configs_server_id ON agent_configs(server_id);

-- Add config column to servers table for quick access
ALTER TABLE servers ADD COLUMN IF NOT EXISTS config JSONB DEFAULT NULL;

-- Update trigger for updated_at
CREATE OR REPLACE FUNCTION update_agent_config_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_agent_config_updated_at ON agent_configs;
CREATE TRIGGER trigger_agent_config_updated_at
    BEFORE UPDATE ON agent_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_agent_config_updated_at();
