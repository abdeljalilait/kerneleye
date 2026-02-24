-- Fix invalid timestamps in traffic_events (dates before 2020 or in the future)
-- These are caused by eBPF timestamp conversion issues

UPDATE traffic_events 
SET last_seen = NOW() 
WHERE last_seen < '2020-01-01'::timestamptz 
   OR last_seen > NOW() + interval '1 year';

UPDATE traffic_events 
SET first_seen = NOW() 
WHERE first_seen < '2020-01-01'::timestamptz 
   OR first_seen > NOW() + interval '1 year';
