-- ============================================================
-- THE QUIET BREACH — Insider Threat Detection
-- File: 04_verify.sql
-- Purpose: Validation queries and Tableau export query
-- Author: Bonica Patterson
-- ============================================================


-- ─── BLOCK 1: Row Count Validation ──────────────────────────
-- Expected: ~16,261 total rows, 50 users, 5 insider threat users

SELECT
    COUNT(*)                                    AS total_logs,
    COUNT(DISTINCT user_id)                     AS unique_users,
    SUM(is_insider_threat)                      AS insider_threat_logs,
    COUNT(DISTINCT CASE WHEN is_insider_threat = 1
          THEN user_id END)                     AS insider_threat_users,
    MIN(date)                                   AS start_date,
    MAX(date)                                   AS end_date
FROM access_logs;


-- ─── BLOCK 2: Threat Score Sanity Check ─────────────────────
-- Insider threats should dominate the top scores.
-- Expected: U007, U014, U023, U031, U045 in top 5 with scores 75–89.

SELECT
    user_id,
    employee_name,
    department,
    MAX(threat_score)   AS peak_threat_score,
    MAX(threat_tier)    AS peak_tier,
    MAX(is_insider_threat) AS is_insider_threat
FROM threat_scores
GROUP BY user_id, employee_name, department
ORDER BY peak_threat_score DESC
LIMIT 10;


-- ─── BLOCK 3: Population Separation Check ───────────────────
-- Verifies the score gap between flagged and normal users.
-- A healthy model shows clear separation — no normal user
-- should be approaching the CRITICAL threshold.

SELECT
    CASE WHEN is_insider_threat = 1
         THEN 'Insider Threat' ELSE 'Normal User' END AS user_group,
    COUNT(DISTINCT user_id)                            AS user_count,
    ROUND(AVG(threat_score), 1)                        AS avg_daily_score,
    ROUND(MAX(threat_score), 1)                        AS max_daily_score,
    ROUND(MIN(threat_score), 1)                        AS min_daily_score
FROM threat_scores
GROUP BY CASE WHEN is_insider_threat = 1
              THEN 'Insider Threat' ELSE 'Normal User' END;


-- ─── BLOCK 4: Weekly Escalation Pattern ─────────────────────
-- Shows how insider threat scores escalate week over week.
-- Useful for verifying the temporal drift pattern is present.

SELECT
    week_number,
    ROUND(AVG(CASE WHEN is_insider_threat = 1
                   THEN threat_score END), 1)  AS avg_threat_score_insiders,
    ROUND(AVG(CASE WHEN is_insider_threat = 0
                   THEN threat_score END), 1)  AS avg_threat_score_normal
FROM threat_scores
GROUP BY week_number
ORDER BY week_number;


-- ─── BLOCK 5: Tableau Export Query ──────────────────────────
-- Run this query and export the results as CSV.
-- This is the dataset loaded into Tableau Public.

SELECT
    ts.user_id,
    ts.employee_name,
    ts.department,
    ts.date,
    ts.week_number,
    ts.daily_events,
    ts.off_hours_events,
    ts.avg_login_hour,
    ts.downloads,
    ts.exports,
    ts.deletes,
    ts.failed_logins,
    ts.unique_resources,
    ts.unique_locations,
    ts.max_session_min,
    ts.baseline_avg_events,
    ts.baseline_off_hours,
    ts.baseline_exfil,
    ts.access_spike_score,
    ts.off_hours_score,
    ts.exfil_score,
    ts.time_shift_score,
    ts.multi_location_score,
    ts.failed_login_score,
    ts.threat_score,
    ts.threat_tier,
    ts.is_insider_threat
FROM threat_scores ts
ORDER BY ts.threat_score DESC, ts.user_id, ts.date;
