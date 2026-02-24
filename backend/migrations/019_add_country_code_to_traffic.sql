-- Add country_code column to traffic_events for flag display
ALTER TABLE traffic_events ADD COLUMN country_code VARCHAR(2);

-- Create index for country_code lookups
CREATE INDEX idx_traffic_country_code ON traffic_events(country_code);
