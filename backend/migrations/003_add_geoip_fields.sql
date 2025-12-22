-- Up
ALTER TABLE traffic_events ADD COLUMN country VARCHAR(255);
ALTER TABLE traffic_events ADD COLUMN city VARCHAR(255);
ALTER TABLE traffic_events ADD COLUMN isp VARCHAR(255);
