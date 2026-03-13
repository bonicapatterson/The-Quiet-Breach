# 🔐 The Quiet Breach
### Insider Threat Detection Using Behavioral Analytics

> *"The most dangerous threats don't announce themselves. They arrive quietly, blend in, and escalate slowly — until the data reveals what the naked eye cannot see."*

[![Tableau Public](https://img.shields.io/badge/Tableau_Public-View_Dashboard-E97627?style=for-the-badge&logo=tableau&logoColor=white)](https://public.tableau.com/app/profile/bonica.patterson/viz/quiet-breach/Story1)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Supabase-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://supabase.com)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)

---

## Table of Contents

- [Overview](#overview)
- [The Story the Data Tells](#the-story-the-data-tells)
- [Methodology](#methodology)
- [Tech Stack](#tech-stack)
- [Repository Structure](#repository-structure)
- [Dashboard Walkthrough](#dashboard-walkthrough)
- [Key Findings](#key-findings)
- [Strategic Recommendations](#strategic-recommendations)
- [Reproducing This Analysis](#reproducing-this-analysis)
- [Threat Score Formula](#threat-score-formula)

---

## Overview

This project simulates an enterprise security operations center (SOC) scenario in which a data analyst is tasked with identifying anomalous employee behavior within access log data. Using **SQL window functions** to establish per-user behavioral baselines and **composite threat scoring** across six signal dimensions, the analysis surfaces five employees whose behavior deviates significantly from their own established patterns — the hallmark of insider threat activity.

The project demonstrates the intersection of data engineering, statistical analysis, and security analytics — a rare combination that enables both technical and non-technical stakeholders to understand, investigate, and act on findings.

**Dataset:** 16,261 simulated access log events across 50 employees over a 90-day observation window (October–December 2024)

**Flagged Users:** 5 employees reached CRITICAL threat tier with peak scores between 75–89 out of 100

---

## The Story the Data Tells

### Act I — The Calm Before (October 2024)

For the first 60 days, all 50 employees behave within expected parameters. Threat scores cluster between 5 and 20 — noise consistent with normal variation in any enterprise environment. Access occurs during business hours. Downloads and exports fall within personal baseline ranges. Nothing appears unusual.

> ![Threat Score Timeline](https://drive.google.com/uc?export=view&id=1mXrJqWcupaJIyxJy-Rz2PccN8Lo5fgJs) `Threat Score Timeline` — the flat left portion of all five lines, Oct 1–Nov 15

---

### Act II — The Drift Begins (Late November 2024)

Around day 61, five employees begin to show subtle but measurable behavioral drift. Login timestamps shift toward evening hours. Access event counts edge upward. A statistical eye would catch it; a human reviewer scanning logs manually would not.

This is precisely the window insider threats exploit. The behavioral change is gradual enough to avoid triggering rule-based alerts, but a rolling baseline model flags it immediately.

> 📸 **Screenshot placement:** `Access Heatmap` — red hotspots visible at hours 2–4 and 20–23 across all days of the week

> 📸 **Screenshot placement:** `Threat Score Timeline` — mid-chart, Nov 15–Dec 1, scores beginning to rise above the HIGH Alert Threshold line at 40

---

### Act III — The Escalation (December 2024)

In the final 30 days, all five flagged employees shift decisively into anomalous territory. Off-hours logins multiply 300–400% above their personal baselines. Download and export actions spike 3–5x. Sessions extend into the early morning hours. In two cases, the same user ID is observed logging in from geographically inconsistent locations within short time windows — a classic impossible travel signal.

By mid-December, four of the five users have breached the CRITICAL threshold (score ≥ 70). The fifth crosses it days later.

> 📸 **Screenshot placement:** `Off-Hours Anomaly` — all five bars showing 378–407 total off-hours events

> 📸 **Screenshot placement:** `Exfil Spike Detection` — bars showing 317–341 total download+export actions per user

> 📸 **Screenshot placement:** `Threat Score Timeline` — right side of chart, Dec 1–28, sharp upward spikes to 75–89

---

### Act IV — The Picture Becomes Clear

When all 50 employees are visualized simultaneously by peak threat tier, the population separates cleanly into two groups: a large mass of LOW and MEDIUM-scoring employees, and five outliers whose boxes dominate the CRITICAL and HIGH quadrants of the treemap.

The gap is not subtle. Normal users cap at a peak score of 46. The five flagged users range from 75 to 89 — a separation of nearly two standard deviations from the normal population's upper bound.

> 📸 **Screenshot placement:** `Threat Level Distribution` treemap — the full 50-employee view showing the five CRITICAL red blocks at bottom-right

> 📸 **Screenshot placement:** `Top Flagged Users` — the visual break between the top 5 red bars (75–89) and the remaining orange bars (40–46)

---

## Methodology

### Behavioral Baseline Construction

Rather than comparing employees against a population average — which penalizes naturally high-volume users — this analysis establishes a **per-user rolling baseline** using a 14-day lookback window. Each user's behavior today is compared only to their own prior two weeks.

This approach eliminates false positives from employees in high-access roles (e.g., IT admins, Finance analysts) and focuses exclusively on **deviation from personal norms**.

```sql
-- 14-day rolling average: each user's prior behavior is their own baseline
AVG(daily_events) OVER (
    PARTITION BY user_id
    ORDER BY date
    ROWS BETWEEN 14 PRECEDING AND 1 PRECEDING
) AS baseline_avg_events
```

### Signal Dimensions

Six behavioral signals are computed and weighted into a composite threat score:

| Signal | Weight | What It Measures |
|--------|--------|-----------------|
| Access Volume Spike | 20% | Z-score of daily events vs. personal 14-day baseline |
| Off-Hours Activity | 25% | Ratio of off-hours logins vs. personal baseline |
| Exfiltration Actions | 30% | Download + export ratio vs. personal baseline |
| Login Time Drift | 15% | Standard deviation shift in typical login hour |
| Multi-Location Anomaly | 5% | Simultaneous or rapid location changes |
| Failed Login Spike | 5% | Credential testing or access attempt patterns |

### Threat Tier Classification

| Tier | Score Range | Interpretation |
|------|-------------|----------------|
| LOW | 0–19 | Within expected behavioral bounds |
| MEDIUM | 20–39 | Elevated — warrants passive monitoring |
| HIGH | 40–69 | Anomalous — active review recommended |
| CRITICAL | 70–100 | Significant deviation — immediate escalation |

---

## Tech Stack

| Layer | Tool | Purpose |
|-------|------|---------|
| Data Generation | Python (pandas, numpy) | Synthetic dataset creation with engineered anomalies |
| Data Storage | PostgreSQL via Supabase | Relational storage, view management |
| Analytics | SQL (Window Functions, CTEs) | Baseline computation, anomaly scoring |
| Visualization | Tableau Public | Interactive story dashboard |

---

## Repository Structure

```
quiet-breach/
│
├── README.md                      # This file
│
├── data/
│   ├── generate_data.py           # Synthetic dataset generator
│   └── access_logs.csv            # Generated raw access logs (16,261 rows)
│
├── sql/
│   ├── 01_create_table.sql        # access_logs table schema
│   ├── 02_user_daily_activity.sql # Aggregated daily view per user
│   ├── 03_threat_scores.sql       # Window functions + composite scoring
│   └── 04_verify.sql              # Validation queries
│
└── exports/
    └── threat_scores_export.csv   # Final scored dataset for Tableau
```

---

## Dashboard Walkthrough

The published Tableau story contains nine slides navigated sequentially:

| Slide | Title | Key Insight |
|-------|-------|-------------|
| 1 | The Quiet Breach (Intro) | Methodology and scope overview |
| 2 | Threat Score Timeline | Behavioral escalation pattern Oct–Dec |
| 3 | Access Heatmap | Off-hours login clustering by hour and day |
| 4 | Off-Hours Anomaly | 378–407 off-hours events per flagged user |
| 5 | Exfil Spike Detection | 317–341 download+export actions per user |
| 6 | Threat Level Distribution | Full org treemap — 5 CRITICAL outliers |
| 7 | Top Flagged Users | Score gap: 75–89 vs. 40–46 cap for normal users |
| 8 | Strategic Recommendations | Five actionable security recommendations |
| 9 | Thank You | Tools, dataset, and contact |

🔗 **[View the live dashboard →](https://public.tableau.com/app/profile/bonica.patterson/viz/quiet-breach/Story1)**

---

## Key Findings

**1. Behavioral drift precedes escalation by ~2 weeks.**
The five flagged users showed measurable score increases beginning around day 61, approximately 14 days before reaching HIGH threshold. This window represents the earliest viable intervention point with a real-time alerting system.

**2. Off-hours access is the strongest individual signal.**
With a 25% composite weight and the highest raw deviation (300–400% above personal baseline), off-hours activity was the single most discriminating feature separating flagged from normal users.

**3. The population separates cleanly.**
No normal user exceeded a peak threat score of 46.1. All five insider threats exceeded 75.0. The 29-point gap between the highest normal user and the lowest flagged user suggests the scoring model has low false-positive risk at a threshold of 70.

**4. Exfiltration signals correlate with off-hours access.**
Download and export spikes co-occurred with off-hours login events in 87% of flagged days, suggesting a consistent pattern of accessing sensitive resources outside monitored hours — consistent with data staging behavior prior to exfiltration.

**5. Multi-location anomalies appeared in late-stage activity.**
Location inconsistencies were detected in 3 of 5 flagged users during the final 2 weeks, suggesting either credential sharing, VPN spoofing, or account compromise as a secondary hypothesis worth investigating.

---

## Strategic Recommendations

**01 — Immediate Action**
Place U007 (William Miller), U014 (Jessica White), U023 (Matthew Scott), U031 (Steven Baker), and U045 (George Edwards) under enhanced monitoring. Restrict access to sensitive resource categories pending HR and legal review. Preserve digital evidence chain-of-custody before any employee contact.

**02 — Real-Time Alerting**
Implement automated alerting when any user's 7-day rolling threat score exceeds 40 (HIGH threshold). The current analysis was performed post-hoc over 90 days. A live pipeline would have surfaced these users in the first week of November — potentially weeks earlier.

**03 — Least-Privilege Access Controls**
Flagged users accessed an average of 8 distinct sensitive resource categories. Normal users accessed 3. Role-based access controls (RBAC) with quarterly access reviews would constrain the blast radius of any future insider threat event.

**04 — Continuous Behavioral Analytics**
The 14-day rolling window model is production-ready and scalable. Deployment as a scheduled SQL job or dbt model against a live SIEM data feed would enable ongoing monitoring across the full employee population at minimal infrastructure cost.

**05 — Insider Threat Response Playbook**
Establish a formal response protocol that includes legal review triggers, HR notification procedures, digital forensics chain-of-custody requirements, and defined escalation paths to avoid tipping off subjects before evidence is secured.

---

## Reproducing This Analysis

### Prerequisites

- Python 3.10+
- A Supabase account (free tier sufficient) or any PostgreSQL instance
- Tableau Public (free)

### Step 1 — Generate the Dataset

```bash
pip install pandas numpy
python data/generate_data.py
```

This produces `access_logs.csv` with 16,261 rows across 50 employees. Five employees (U007, U014, U023, U031, U045) are seeded as insider threats with engineered behavioral drift beginning at day 61.

### Step 2 — Load into Supabase

1. Create a new Supabase project
2. In the SQL Editor, run `sql/01_create_table.sql` to create the schema
3. Import `access_logs.csv` via Table Editor → Import CSV
4. Verify with:

```sql
SELECT COUNT(*), COUNT(DISTINCT user_id), MIN(date), MAX(date)
FROM access_logs;
-- Expected: 16261 rows, 50 users, 2024-10-01 to 2024-12-28
```

### Step 3 — Build the Analytics Layer

Run the following SQL files in order in the Supabase SQL Editor:

```bash
sql/02_user_daily_activity.sql   # Creates user_daily_activity view
sql/03_threat_scores.sql         # Creates threat_scores view with window functions
sql/04_verify.sql                # Validates scores — insider threats should dominate top results
```

Validate output:

```sql
SELECT user_id, employee_name, MAX(threat_score) as peak_score, MAX(threat_tier) as peak_tier
FROM threat_scores
GROUP BY user_id, employee_name
ORDER BY peak_score DESC
LIMIT 10;
-- Expected: U007, U014, U023, U031, U045 in top 5 with scores 75–89, tier CRITICAL
```

### Step 4 — Export for Tableau

Run the export query from `sql/04_verify.sql` (Block 5) and download as CSV, or use the pre-computed `exports/threat_scores_export.csv`.

### Step 5 — Rebuild in Tableau Public

1. Connect to `threat_scores_export.csv` as a Text File data source
2. Also connect `access_logs.csv` as a second data source
3. Build the six sheets following the sheet specifications below
4. Assemble into a Story with nine story points

#### Sheet Specifications

| Sheet | Data Source | X Axis | Y Axis | Color | Filter |
|-------|------------|--------|--------|-------|--------|
| Threat Score Timeline | threat_scores_export | Date (Exact) | AVG(Threat Score) | Employee Name | Is Insider Threat = 1 |
| Access Heatmap | access_logs | Hour Of Day (Dim) | Day Of Week | CNT(Log Id) | Is Insider Threat = 1 |
| Off-Hours Anomaly | threat_scores_export | SUM(Off Hours Events) | Employee Name | Employee Name | Is Insider Threat = 1 |
| Exfil Spike Detection | threat_scores_export | SUM(Total Exfil Actions) | Employee Name | Employee Name | Is Insider Threat = 1 |
| Threat Level Distribution | threat_scores_export | — | — | Threat Tier | None (all 50 employees) |
| Top Flagged Users | threat_scores_export | MAX(Threat Score) | Employee Name | Is Insider Threat | Top 10 by MAX(Threat Score) |

#### Color Standards

| Purpose | Hex |
|---------|-----|
| Background (all sheets) | `#0D1117` |
| CRITICAL / Insider Threat | `#FF3B3B` |
| HIGH | `#FF8C00` |
| MEDIUM | `#FFD700` |
| LOW | `#1C2333` |
| Chart subtitle text | `#A0A0A0` |
| Reference lines | `#FF4444` (dashed) |

---

## Threat Score Formula

```
Threat Score = MIN(
    (access_spike_score  / 5) × 20  +   -- Access volume z-score
    (off_hours_score     / 5) × 25  +   -- Off-hours ratio
    (exfil_score         / 5) × 30  +   -- Download+export ratio  
    (time_shift_score    / 5) × 15  +   -- Login hour drift z-score
    (multi_location_score / 1.5) × 5 +  -- Location anomaly flag
    (failed_login_score  / 2) × 5,      -- Failed login indicator
    100
)
```

All sub-scores are normalized to a 0–5 scale before weighting, ensuring no single signal can dominate the composite. The final score is capped at 100.

---

## Design Decisions and Limitations

**Why synthetic data?**
Real enterprise access logs contain PII and are subject to data handling restrictions that preclude public sharing. Synthetic data generated with realistic statistical properties enables full reproducibility while demonstrating the same analytical techniques that would apply to production data.

**Why per-user baselines rather than population baselines?**
Population-average comparisons systematically flag high-volume roles (IT, Finance) as anomalous regardless of their actual behavior change. Per-user baselines measure deviation from self — a more precise and less noisy signal for behavioral analytics.

**Limitations**
- The 14-day baseline window is insufficient for users who joined recently or returned from extended leave. A production system would require a minimum observation period before scoring begins.
- The current model does not account for known scheduled events (e.g., quarter-end reporting periods that legitimately elevate Finance team activity). A production deployment would integrate a business calendar suppression layer.
- Threat scores are indicators, not conclusions. All flagged users require human investigation before any action is taken.

---

*Built with SQL, Python, and Tableau Public.*
*Analysis by Bonica Patterson*
