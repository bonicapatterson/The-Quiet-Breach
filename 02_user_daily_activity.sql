-- ============================================================
-- THE QUIET BREACH — Insider Threat Detection
-- File: 02_user_daily_activity.sql
-- Purpose: Aggregate raw logs into daily activity per user.
--          This view feeds the threat scoring engine.
-- Author: Bonica Patterson
-- ============================================================

CREATE OR REPLACE VIEW user_daily_activity AS
SELECT
    user_id,
    employee_name,
    department,
    date,
    week_number,

    -- Volume signals
    COUNT(*)                                                        AS daily_events,
    SUM(is_off_hours)                                               AS off_hours_events,
    ROUND(AVG(hour_of_day), 2)                                      AS avg_login_hour,

    -- Exfiltration signals
    SUM(CASE WHEN action_type = 'DOWNLOAD'     THEN 1 ELSE 0 END)  AS downloads,
    SUM(CASE WHEN action_type = 'EXPORT'       THEN 1 ELSE 0 END)  AS exports,
    SUM(CASE WHEN action_type = 'DELETE'       THEN 1 ELSE 0 END)  AS deletes,

    -- Access anomaly signals
    SUM(CASE WHEN action_type = 'FAILED_LOGIN' THEN 1 ELSE 0 END)  AS failed_logins,
    MAX(session_duration_min)                                        AS max_session_min,
    COUNT(DISTINCT resource_accessed)                                AS unique_resources,
    COUNT(DISTINCT location)                                         AS unique_locations,

    -- Ground truth label
    MAX(is_insider_threat)                                           AS is_insider_threat

FROM access_logs
GROUP BY user_id, employee_name, department, date, week_number;
