-- Add client_token and allow null api_key for pending servers
ALTER TABLE servers ADD COLUMN client_token VARCHAR(64) UNIQUE;
ALTER TABLE servers ALTER COLUMN api_key DROP NOT NULL;
CREATE INDEX idx_servers_client_token ON servers(client_token);
