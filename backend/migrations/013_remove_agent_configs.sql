-- Remove agent_configs table - configuration now handled via agent flags

-- Drop trigger
DROP TRIGGER IF EXISTS trigger_agent_config_updated_at ON agent_configs;

-- Drop table
DROP TABLE IF EXISTS agent_configs;

-- Note: Keeping the 'config' column in servers table as it may be used for other purposes
