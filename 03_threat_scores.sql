-- ============================================================
-- THE QUIET BREACH — Insider Threat Detection
-- File: 03_threat_scores.sql
-- Purpose: Compute per-user behavioral baselines using window
--          functions, then score each day against those baselines.
--
-- Key Design Decisions:
--   - Baselines use ROWS BETWEEN 14 PRECEDING AND 1 PRECEDING
--     so today's behavior never contaminates the baseline.
--   - Each signal is normalized to a 0-5 scale before weighting
--     so no single dimension can dominate the composite score.
--   - Scores require at least a 14-day history (baseline IS NOT NULL)
--     to avoid false positives in a user's first two weeks.
--
-- Author: Bonica Patterson
-- ============================================================

CREATE OR REPLACE VIEW threat_scores AS

-- ─── CTE 1: Rolling Baselines ───────────────────────────────
-- For each user-day, compute 14-day lookback statistics
-- using only prior days (ROWS BETWEEN 14 PRECEDING AND 1 PRECEDING).
-- PARTITION BY user_id ensures each user has their own baseline.

WITH rolling_baseline AS (
    SELECT
        user_id,
        employee_name,
        department,
        date,
        week_number,
        daily_events,
        off_hours_events,
        avg_login_hour,
        downloads,
        exports,
        deletes,
        failed_logins,
        max_session_min,
        unique_resources,
        unique_locations,
        is_insider_threat,

        -- Rolling mean: average daily activity in prior 14 days
        AVG(daily_events) OVER (
            PARTITION BY user_id
            ORDER BY date
            ROWS BETWEEN 14 PRECEDING AND 1 PRECEDING
        ) AS baseline_avg_events,

        -- Rolling mean: off-hours events in prior 14 days
        AVG(off_hours_events) OVER (
            PARTITION BY user_id
            ORDER BY date
            ROWS BETWEEN 14 PRECEDING AND 1 PRECEDING
        ) AS baseline_off_hours,

        -- Rolling mean: combined download+export (exfil proxy) prior 14 days
        AVG(downloads + exports) OVER (
            PARTITION BY user_id
            ORDER BY date
            ROWS BETWEEN 14 PRECEDING AND 1 PRECEDING
        ) AS baseline_exfil,

        -- Rolling standard deviation of daily events (volatility baseline)
        STDDEV(daily_events) OVER (
            PARTITION BY user_id
            ORDER BY date
            ROWS BETWEEN 14 PRECEDING AND 1 PRECEDING
        ) AS stddev_events,

        -- Rolling mean and stddev of login hour (time-of-day pattern baseline)
        AVG(avg_login_hour) OVER (
            PARTITION BY user_id
            ORDER BY date
            ROWS BETWEEN 14 PRECEDING AND 1 PRECEDING
        ) AS baseline_avg_hour,

        STDDEV(avg_login_hour) OVER (
            PARTITION BY user_id
            ORDER BY date
            ROWS BETWEEN 14 PRECEDING AND 1 PRECEDING
        ) AS stddev_hour

    FROM user_daily_activity
),

-- ─── CTE 2: Individual Signal Scores ────────────────────────
-- Convert each raw signal into a 0-5 normalized anomaly score.
-- Higher = more anomalous relative to personal baseline.

scored AS (
    SELECT
        *,

        -- ACCESS SPIKE SCORE
        -- Z-score of today's event count vs. personal baseline.
        -- Positive only — we flag spikes, not drops.
        CASE
            WHEN stddev_events > 0 AND baseline_avg_events IS NOT NULL
            THEN ROUND(LEAST(
                GREATEST((daily_events - baseline_avg_events) / NULLIF(stddev_events, 0), 0),
                5), 2)
            ELSE 0
        END AS access_spike_score,

        -- OFF-HOURS SCORE
        -- Ratio of today's off-hours events vs. personal off-hours baseline.
        -- If user never had off-hours activity before, any occurrence is anomalous.
        CASE
            WHEN baseline_off_hours > 0.2
            THEN ROUND(LEAST(off_hours_events::NUMERIC / NULLIF(baseline_off_hours, 0), 5), 2)
            ELSE LEAST(off_hours_events * 0.8, 5)
        END AS off_hours_score,

        -- EXFIL SCORE
        -- Ratio of today's download+export actions vs. personal exfil baseline.
        CASE
            WHEN baseline_exfil > 0.3
            THEN ROUND(LEAST((downloads + exports)::NUMERIC / NULLIF(baseline_exfil, 0), 5), 2)
            ELSE LEAST((downloads + exports) * 0.6, 5)
        END AS exfil_score,

        -- TIME SHIFT SCORE
        -- Z-score of today's average login hour vs. personal login time baseline.
        -- Captures gradual drift toward unusual login hours.
        CASE
            WHEN stddev_hour > 0
            THEN ROUND(LEAST(
                ABS(avg_login_hour - baseline_avg_hour) / NULLIF(stddev_hour, 0),
                5), 2)
            ELSE 0
        END AS time_shift_score,

        -- MULTI-LOCATION SCORE
        -- Binary flag: did the user log in from multiple locations in one day?
        CASE WHEN unique_locations > 1 THEN 1.5 ELSE 0 END AS multi_location_score,

        -- FAILED LOGIN SCORE
        -- Tiered: multiple failed logins suggest credential testing.
        CASE
            WHEN failed_logins >= 5 THEN 2.0
            WHEN failed_logins >= 3 THEN 1.5
            WHEN failed_logins >= 1 THEN 0.8
            ELSE 0
        END AS failed_login_score

    FROM rolling_baseline
),

-- ─── CTE 3: Composite Score + Tier Classification ───────────
-- Weight and combine all signal scores into a single threat score.
-- Weights reflect relative importance in insider threat literature:
--   Exfil (30%) > Off-Hours (25%) > Volume Spike (20%) >
--   Time Shift (15%) > Multi-Location (5%) > Failed Logins (5%)

final AS (
    SELECT
        *,

        -- COMPOSITE THREAT SCORE (0–100, capped)
        ROUND(LEAST(
            (access_spike_score  / 5.0) * 20 +
            (off_hours_score     / 5.0) * 25 +
            (exfil_score         / 5.0) * 30 +
            (time_shift_score    / 5.0) * 15 +
            (multi_location_score / 1.5) * 5  +
            (failed_login_score  / 2.0) * 5,
        100), 1) AS threat_score,

        -- THREAT TIER
        CASE
            WHEN ROUND(LEAST(
                (access_spike_score  / 5.0) * 20 +
                (off_hours_score     / 5.0) * 25 +
                (exfil_score         / 5.0) * 30 +
                (time_shift_score    / 5.0) * 15 +
                (multi_location_score / 1.5) * 5  +
                (failed_login_score  / 2.0) * 5,
            100), 1) >= 70 THEN 'CRITICAL'
            WHEN ROUND(LEAST(
                (access_spike_score  / 5.0) * 20 +
                (off_hours_score     / 5.0) * 25 +
                (exfil_score         / 5.0) * 30 +
                (time_shift_score    / 5.0) * 15 +
                (multi_location_score / 1.5) * 5  +
                (failed_login_score  / 2.0) * 5,
            100), 1) >= 40 THEN 'HIGH'
            WHEN ROUND(LEAST(
                (access_spike_score  / 5.0) * 20 +
                (off_hours_score     / 5.0) * 25 +
                (exfil_score         / 5.0) * 30 +
                (time_shift_score    / 5.0) * 15 +
                (multi_location_score / 1.5) * 5  +
                (failed_login_score  / 2.0) * 5,
            100), 1) >= 20 THEN 'MEDIUM'
            ELSE 'LOW'
        END AS threat_tier

    FROM scored
)

-- Final output: exclude early rows without sufficient baseline history
SELECT * FROM final
WHERE baseline_avg_events IS NOT NULL
ORDER BY user_id, date;
