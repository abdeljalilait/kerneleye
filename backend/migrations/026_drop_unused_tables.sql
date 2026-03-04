-- Migration: Drop unused ip_stats and audit_log tables
-- Created: 2026-03-04
-- These tables were created in the initial schema but are never queried
-- by the application.

DROP TABLE IF EXISTS ip_stats;
DROP TABLE IF EXISTS audit_log;
