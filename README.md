# Cyber Fusion SOC Alert Scorecard

A portfolio project simulating the analytics workflow of a **Data Analyst on a
Cyber Fusion / Enterprise Protection & Operations (EPO) team**: multi-source
security alert data → PySpark ETL pipeline → anomaly detection →
Power BI-style scorecard dashboard.

Built to demonstrate the specific gap between a general data-analytics
background and a security-data-analytics role: working with SOC/SIEM-shaped
data, security-relevant metrics (SLA breach, false-positive rate, alert
severity mix), and translating them into a stakeholder-facing scorecard.

> **This project uses 100% synthetic data.** No real SIEM, EDR, customer, or
> employer data is used anywhere in this repository. See
> [Data note](#data-note--assumptions) below.

---

## Why this project

Mapped directly against the target JD's core responsibilities:

| JD requirement | Where it's demonstrated |
|---|---|
| Develop/maintain dashboards, reports, scorecards | `dashboard/soc_scorecard.html` |
| Analyze multi-source data for trends/anomalies | `notebooks/anomaly_detection_analysis.ipynb` |
| Use SQL, Python, Power BI-style visualization, Databricks | `etl/etl_pipeline.py` (PySpark), notebook (pandas/matplotlib) |
| ETL / data pipeline development | `etl/etl_pipeline.py` — ingest → validate → transform → aggregate → load |
| Document data definitions, assumptions, workflows | This README |
| Security data sources / SOC-style analytics | Entire dataset design — see below |

---

## Architecture

```
data/generate_synthetic_soc_data.py   →  raw CSVs (source-system shaped)
        │
        ▼
etl/etl_pipeline.py  (PySpark, Databricks-notebook-ready)
        │  1. Ingest      raw multi-source CSVs
        │  2. Validate    schema + null/range checks, quarantine bad rows
        │  3. Transform   enrichment joins (asset + analyst), derived fields
        │  4. Aggregate   6 scorecard-grain tables
        │  5. Load        curated CSVs (→ Delta tables in a real workspace)
        ▼
data/curated/*.csv
        │
        ├──▶ notebooks/anomaly_detection_analysis.ipynb   (analysis layer)
        └──▶ dashboard/soc_scorecard.html                  (presentation layer)
```

The ETL script is written as a Databricks-notebook-compatible `.py` file
(`# COMMAND ----------` cell markers) so it can be imported directly into a
Databricks workspace via *Workspace > Import*. Locally it runs against a
local Spark session; in a real deployment, `RAW_PATH`/`CURATED_PATH` become
Unity Catalog volumes or DBFS paths, and the final write becomes
`saveAsTable(...)` against Delta tables.

---

## Data definitions

**Alert record** (`soc_alerts_raw.csv`, one row per triggered alert):

| Field | Definition |
|---|---|
| `alert_id` | Unique alert identifier |
| `alert_timestamp` | When the alert fired |
| `source_system` | Originating tool: SIEM, EDR, Email Gateway, Firewall, CASB, IDS/IPS |
| `alert_type` | Alert category (mapped loosely to MITRE ATT&CK-style tactic names, e.g. "Privilege Escalation Attempt") |
| `severity` | Critical / High / Medium / Low |
| `assigned_analyst` | Analyst who triaged the alert |
| `asset_id` | Affected asset, joined against the asset inventory |
| `status` | Open / In Progress / Closed |
| `time_to_triage_minutes` | Minutes from alert firing to analyst triage |
| `false_positive` | Whether the alert was determined to be a false positive |

**Derived fields** (added in the ETL transform stage, not present in the raw
extract — this separation is deliberate, to mirror how enrichment is a
pipeline responsibility, not a source-system one):

| Field | Definition |
|---|---|
| `sla_target_minutes` | SLA target by severity: Critical 30 / High 120 / Medium 480 / Low 1440 |
| `sla_breached_calc` | `time_to_triage_minutes > sla_target_minutes` |
| `is_business_hours` | Alert fired between 08:00–18:00 |
| `asset_criticality`, `business_unit`, `region` | Joined from the asset inventory |
| `analyst_shift` | Joined from the analyst roster (Day / Evening / Night) |

**Scorecard-grain tables** (`data/curated/`): `kpi_summary`,
`daily_volume_by_source`, `severity_by_source`, `analyst_performance`,
`risk_by_business_unit`, `alerts_enriched`.

---

## Data note & assumptions

- All alert, asset, and analyst data is **synthetically generated**
  (`data/generate_synthetic_soc_data.py`), seeded for reproducibility.
- Alert-type names are modeled on publicly documented SOC/SIEM concepts and
  MITRE ATT&CK tactic naming conventions — not drawn from any real detection
  library.
- Alert volume is deliberately **not uniform**: 60% is business-hours
  weighted, and **3 volume-spike days are intentionally injected** into one
  source system so the anomaly-detection notebook has a real signal to find.
  This is disclosed here rather than presented as an organic finding.
- SLA targets (Critical 30min / High 2h / Medium 8h / Low 24h) are a
  reasonable illustrative default, not a real organization's policy.
- False-positive probability and time-to-triage are modeled with
  severity-correlated distributions (critical alerts triage faster on
  average, low-severity alerts have a higher false-positive rate) plus an
  8% injected long-tail for realistic SLA-breach variance.

---

## Anomaly detection methodology

Volume anomalies are flagged using a **14-day rolling mean + 3-sigma
threshold** per source system — a standard, easily-explained control-chart
method appropriate as a first-pass detector and for stakeholder
communication. The notebook documents this explicitly as a starting point;
a production system would likely layer in a seasonal-hybrid ESD or
Isolation Forest approach for multivariate anomaly detection.

---

## Running it

```bash
pip install pandas numpy pyspark jupyter matplotlib

python data/generate_synthetic_soc_data.py    # generate raw data
python etl/etl_pipeline.py                     # run ETL, write curated tables
jupyter nbconvert --to notebook --execute --inplace notebooks/anomaly_detection_analysis.ipynb
open dashboard/soc_scorecard.html              # view the scorecard
```

## Repository structure

```
soc-fusion-analytics/
├── data/
│   ├── generate_synthetic_soc_data.py
│   ├── soc_alerts_raw.csv, asset_inventory.csv, analyst_roster.csv
│   └── curated/           # ETL output tables
├── etl/
│   └── etl_pipeline.py    # PySpark, Databricks-notebook-ready
├── notebooks/
│   └── anomaly_detection_analysis.ipynb
├── dashboard/
│   └── soc_scorecard.html # Power BI-style scorecard (standalone, no server needed)
└── README.md
```

## Note on the dashboard

`soc_scorecard.html` is built as a standalone HTML/CSS/JS mockup of a
Power BI scorecard — chosen because this environment can't produce a real
`.pbix` file. The KPI values, chart data, and tables are all computed from
the actual curated pipeline output (not hand-typed), so the numbers are
real outputs of the ETL + anomaly-detection steps above. Rebuilding the same
visuals as an actual Power BI report (cards, a line chart with an
anomaly reference line, and matrix visuals against the curated CSVs) would
be a direct, fast follow-up if a live `.pbix` is wanted for the application.
