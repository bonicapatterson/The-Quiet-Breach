-- ============================================================
-- THE QUIET BREACH — Insider Threat Detection
-- File: 01_create_table.sql
-- Purpose: Create the raw access logs table
-- Author: Bonica Patterson
-- ============================================================

CREATE TABLE IF NOT EXISTS access_logs (
    log_id                 BIGINT PRIMARY KEY,
    user_id                TEXT NOT NULL,
    employee_name          TEXT,
    department             TEXT,
    role                   TEXT,
    timestamp              TIMESTAMP,
    date                   DATE,
    hour_of_day            INTEGER,
    day_of_week            TEXT,
    week_number            INTEGER,
    resource_accessed      TEXT,
    action_type            TEXT,
    location               TEXT,
    session_duration_min   INTEGER,
    is_off_hours           INTEGER,   -- 1 if hour < 7 or hour > 19, else 0
    is_weekend             INTEGER,   -- 1 if Saturday or Sunday, else 0
    is_insider_threat      INTEGER    -- Ground truth label (1 = seeded threat)
);
