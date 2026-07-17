"""
generate_synthetic_soc_data.py

Generates a synthetic, multi-source SOC (Security Operations Center) alert
dataset for the Cyber Fusion Analytics portfolio project.

IMPORTANT: All data below is synthetically generated for demonstration
purposes. No real alert data, customer data, or proprietary information
from any employer is used or represented here. Field names and value
distributions are modeled on publicly documented SOC/SIEM concepts
(MITRE ATT&CK tactic names, common alert sources, standard SOC severity
tiers) to be realistic without being tied to any real system.

Design intent: mirror the kind of multi-source data an Enterprise
Protection & Operations (EPO) / Cyber Fusion data analyst would actually
touch — SIEM alerts, EDR detections, email gateway flags, firewall
blocks — joined against an asset inventory and an analyst roster, so the
downstream ETL pipeline has to do real integration work (not just clean
one flat file).
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta

RNG = np.random.default_rng(seed=42)

N_ALERTS = 12000
N_DAYS = 90
END_DATE = datetime(2026, 7, 15)
START_DATE = END_DATE - timedelta(days=N_DAYS)

SOURCE_SYSTEMS = ["SIEM", "EDR", "Email Gateway", "Firewall", "Cloud Access Security (CASB)", "IDS/IPS"]
SOURCE_WEIGHTS = [0.32, 0.22, 0.18, 0.14, 0.08, 0.06]

# Alert types loosely mapped to MITRE ATT&CK tactic families for realism
ALERT_TYPES = {
    "SIEM": ["Anomalous Login Pattern", "Privilege Escalation Attempt", "Brute Force Attempt", "Lateral Movement Indicator"],
    "EDR": ["Suspicious Process Execution", "Ransomware Behavior Pattern", "Unsigned Binary Execution", "Credential Dumping Indicator"],
    "Email Gateway": ["Phishing Attempt", "Business Email Compromise Indicator", "Malicious Attachment", "Spoofed Sender Domain"],
    "Firewall": ["Blocked Outbound C2 Traffic", "Port Scan Detected", "Unusual Outbound Data Volume", "Blocked Known-Bad IP"],
    "Cloud Access Security (CASB)": ["Impossible Travel Login", "Unsanctioned App Access", "Anomalous Data Download Volume"],
    "IDS/IPS": ["Exploit Attempt Signature Match", "Malware Signature Match", "Protocol Anomaly"],
}

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEVERITY_WEIGHTS = [0.06, 0.19, 0.42, 0.33]

BUSINESS_UNITS = ["Retail Banking", "Asset Servicing", "Global Markets", "Corporate Functions", "Fund Services", "Technology"]
REGIONS = ["NA", "EMEA", "APAC"]

N_ANALYSTS = 14
ANALYSTS = [f"Analyst_{i:02d}" for i in range(1, N_ANALYSTS + 1)]
ANALYST_SHIFT = {a: RNG.choice(["Day", "Evening", "Night"], p=[0.45, 0.35, 0.20]) for a in ANALYSTS}

N_ASSETS = 800
ASSET_IDS = [f"AST-{i:05d}" for i in range(1, N_ASSETS + 1)]
ASSET_CRITICALITY = RNG.choice(["Tier 1 - Critical", "Tier 2 - High", "Tier 3 - Standard"], size=N_ASSETS, p=[0.10, 0.25, 0.65])
ASSET_BU = RNG.choice(BUSINESS_UNITS, size=N_ASSETS)
ASSET_REGION = RNG.choice(REGIONS, size=N_ASSETS, p=[0.45, 0.35, 0.20])

asset_df = pd.DataFrame({
    "asset_id": ASSET_IDS,
    "asset_criticality": ASSET_CRITICALITY,
    "business_unit": ASSET_BU,
    "region": ASSET_REGION,
})

# SLA targets (minutes) by severity — used later to flag SLA breaches
SLA_TARGET_MINUTES = {"Critical": 30, "High": 120, "Medium": 480, "Low": 1440}


def random_timestamps(n, start, end):
    """Alert volume is not uniform: business-hours bias + a few injected spike days
    (to give the anomaly-detection step something real to find)."""
    total_minutes = int((end - start).total_seconds() // 60)
    base = RNG.integers(0, total_minutes, size=n)
    ts = np.array([start + timedelta(minutes=int(m)) for m in base])

    # Business-hours weighting: resample 60% of timestamps into 08:00-19:00 local-equivalent
    business_mask = RNG.random(n) < 0.6
    for i in np.where(business_mask)[0]:
        d = ts[i].date()
        hour = RNG.integers(8, 19)
        minute = RNG.integers(0, 60)
        ts[i] = datetime.combine(d, datetime.min.time()) + timedelta(hours=int(hour), minutes=int(minute))
    return ts


def inject_spike_days(timestamps, source_systems, n_spike_days=3):
    """Pick a few days and a source system, and densify alerts on that day/source
    to simulate a real incident burst the anomaly detector should catch."""
    spike_days = RNG.choice(pd.date_range(START_DATE, END_DATE, freq="D"), size=n_spike_days, replace=False)
    spike_source = RNG.choice(SOURCE_SYSTEMS)
    extra_rows = []
    for day in spike_days:
        n_extra = int(RNG.integers(80, 160))
        for _ in range(n_extra):
            hour = RNG.integers(0, 24)
            minute = RNG.integers(0, 60)
            extra_rows.append((pd.Timestamp(day) + timedelta(hours=int(hour), minutes=int(minute)), spike_source))
    return extra_rows, [pd.Timestamp(d).date() for d in spike_days], spike_source


def build_dataset():
    timestamps = random_timestamps(N_ALERTS, START_DATE, END_DATE)
    sources = RNG.choice(SOURCE_SYSTEMS, size=N_ALERTS, p=SOURCE_WEIGHTS)
    extra_rows, spike_days, spike_source = inject_spike_days(timestamps, sources)

    rows = []
    for ts, src in zip(timestamps, sources):
        rows.append((ts, src))
    rows.extend(extra_rows)

    n = len(rows)
    alert_types = [RNG.choice(ALERT_TYPES[src]) for _, src in rows]
    severities = RNG.choice(SEVERITIES, size=n, p=SEVERITY_WEIGHTS)
    analysts = RNG.choice(ANALYSTS, size=n)
    assets = RNG.choice(ASSET_IDS, size=n)

    # Time-to-triage: correlated with severity (critical triaged faster on average)
    # plus a long tail, plus intentionally-injected SLA breaches for realism.
    severity_scale = {"Critical": 18, "High": 70, "Medium": 240, "Low": 600}
    ttt = np.array([
        max(1, RNG.gamma(shape=2.0, scale=severity_scale[s]))
        for s in severities
    ])
    # 8% of alerts get a deliberately extended triage time (SLA breach injection)
    breach_mask = RNG.random(n) < 0.08
    ttt[breach_mask] *= RNG.uniform(3, 8, size=breach_mask.sum())

    # False positive flag: Low/Medium severity alerts are far more likely to be FPs
    fp_prob = np.array([{"Critical": 0.03, "High": 0.09, "Medium": 0.28, "Low": 0.45}[s] for s in severities])
    false_positive = RNG.random(n) < fp_prob

    status = np.where(
        RNG.random(n) < 0.96, "Closed",
        RNG.choice(["Open", "In Progress"], size=n)
    )

    df = pd.DataFrame({
        "alert_id": [f"ALT-{100000+i}" for i in range(n)],
        "alert_timestamp": [r[0] for r in rows],
        "source_system": [r[1] for r in rows],
        "alert_type": alert_types,
        "severity": severities,
        "assigned_analyst": analysts,
        "asset_id": assets,
        "status": status,
        "time_to_triage_minutes": np.round(ttt, 1),
        "false_positive": false_positive,
    })

    df = df.merge(asset_df, on="asset_id", how="left")
    df["analyst_shift"] = df["assigned_analyst"].map(ANALYST_SHIFT)
    df["sla_target_minutes"] = df["severity"].map(SLA_TARGET_MINUTES)
    df["sla_breached"] = df["time_to_triage_minutes"] > df["sla_target_minutes"]

    df = df.sort_values("alert_timestamp").reset_index(drop=True)
    return df, spike_days, spike_source


if __name__ == "__main__":
    alerts_df, spike_days, spike_source = build_dataset()

    # Raw source extract: only what the source system itself would emit.
    # Asset/analyst attributes and SLA derivations are added later by the
    # ETL pipeline's enrichment step, not baked in here.
    raw_cols = [
        "alert_id", "alert_timestamp", "source_system", "alert_type", "severity",
        "assigned_analyst", "asset_id", "status", "time_to_triage_minutes", "false_positive",
    ]
    alerts_df[raw_cols].to_csv("/home/claude/soc-fusion-analytics/data/soc_alerts_raw.csv", index=False)
    asset_df.to_csv("/home/claude/soc-fusion-analytics/data/asset_inventory.csv", index=False)

    analyst_df = pd.DataFrame({
        "analyst_id": ANALYSTS,
        "shift": [ANALYST_SHIFT[a] for a in ANALYSTS],
    })
    analyst_df.to_csv("/home/claude/soc-fusion-analytics/data/analyst_roster.csv", index=False)

    print(f"Generated {len(alerts_df):,} alerts across {N_DAYS} days.")
    print(f"Injected volume-spike days (for anomaly detection to find): {spike_days} on source '{spike_source}'")
    print(alerts_df.head(3).to_string())
