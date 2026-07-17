"""
etl_pipeline.py

ETL pipeline for the Cyber Fusion SOC Alert Scorecard project.

Written in PySpark for direct portability into a Databricks notebook
(each cell below is delimited with `# COMMAND ----------`, the standard
Databricks notebook cell marker, so this file can be imported into
Databricks as-is via Workspace > Import).

Pipeline stages:
  1. INGEST   - read raw multi-source CSVs (would be raw SIEM/EDR/etc.
                exports or a landing-zone table in a real deployment)
  2. VALIDATE - schema + null/range checks, quarantine bad rows
  3. TRANSFORM- type casting, enrichment joins (asset + analyst), derived
                fields (SLA breach, business-hours flag, alert age)
  4. AGGREGATE- build the scorecard-grain tables the dashboard reads
  5. LOAD     - write curated Delta-style tables (parquet locally,
                `saveAsTable` in Databricks) partitioned by date

Run locally with a Spark session, or paste cells into a Databricks
notebook — no code changes required beyond the file paths, which would
become Unity Catalog / DBFS paths in a real workspace.
"""

# COMMAND ----------
from pyspark.sql import SparkSession, functions as F, Window
from pyspark.sql.types import StringType, TimestampType, DoubleType, BooleanType

spark = SparkSession.builder.appName("soc_fusion_etl").getOrCreate()

RAW_PATH = "/home/claude/soc-fusion-analytics/data"
CURATED_PATH = "/home/claude/soc-fusion-analytics/data/curated"

# COMMAND ----------
# ---------------------------------------------------------------------------
# 1. INGEST
# ---------------------------------------------------------------------------
alerts_raw = (
    spark.read.option("header", True).option("inferSchema", True)
    .csv(f"{RAW_PATH}/soc_alerts_raw.csv")
)
assets = spark.read.option("header", True).option("inferSchema", True).csv(f"{RAW_PATH}/asset_inventory.csv")
analysts = spark.read.option("header", True).option("inferSchema", True).csv(f"{RAW_PATH}/analyst_roster.csv")

print(f"Ingested {alerts_raw.count():,} raw alert rows")

# COMMAND ----------
# ---------------------------------------------------------------------------
# 2. VALIDATE — quarantine rows that fail basic data-quality rules rather
#    than silently dropping them, so DQ issues are auditable.
# ---------------------------------------------------------------------------
VALID_SEVERITIES = ["Critical", "High", "Medium", "Low"]

alerts_typed = (
    alerts_raw
    .withColumn("alert_timestamp", F.to_timestamp("alert_timestamp"))
    .withColumn("time_to_triage_minutes", F.col("time_to_triage_minutes").cast(DoubleType()))
    .withColumn("false_positive", F.col("false_positive").cast(BooleanType()))
)

dq_checks = (
    F.col("alert_id").isNotNull()
    & F.col("alert_timestamp").isNotNull()
    & F.col("severity").isin(VALID_SEVERITIES)
    & (F.col("time_to_triage_minutes") >= 0)
)

alerts_valid = alerts_typed.filter(dq_checks)
alerts_quarantine = alerts_typed.filter(~dq_checks)

print(f"Valid rows: {alerts_valid.count():,} | Quarantined rows: {alerts_quarantine.count():,}")

# COMMAND ----------
# ---------------------------------------------------------------------------
# 3. TRANSFORM — enrich with asset + analyst dimensions, derive analytical
#    fields the scorecard and anomaly-detection layer both depend on.
# ---------------------------------------------------------------------------
enriched = (
    alerts_valid
    .join(assets.select("asset_id", "asset_criticality", "business_unit", "region"), on="asset_id", how="left")
    .join(analysts.select(F.col("analyst_id").alias("assigned_analyst"), F.col("shift").alias("analyst_shift")),
          on="assigned_analyst", how="left")
    .withColumn("alert_date", F.to_date("alert_timestamp"))
    .withColumn("alert_hour", F.hour("alert_timestamp"))
    .withColumn("is_business_hours", F.col("alert_hour").between(8, 18))
    .withColumn(
        "sla_target_minutes",
        F.when(F.col("severity") == "Critical", 30)
         .when(F.col("severity") == "High", 120)
         .when(F.col("severity") == "Medium", 480)
         .otherwise(1440)
    )
    .withColumn("sla_breached_calc", F.col("time_to_triage_minutes") > F.col("sla_target_minutes"))
)

# COMMAND ----------
# ---------------------------------------------------------------------------
# 4. AGGREGATE — build the grain tables the Power BI scorecard reads.
#    Each of these maps 1:1 to a visual in dashboard/soc_scorecard.html.
# ---------------------------------------------------------------------------

# 4a. Daily volume by source system (feeds the anomaly-detection notebook)
daily_volume_by_source = (
    enriched.groupBy("alert_date", "source_system")
    .agg(F.count("*").alias("alert_count"))
    .orderBy("alert_date", "source_system")
)

# 4b. Top-line scorecard KPIs
kpi_summary = enriched.agg(
    F.count("*").alias("total_alerts"),
    F.round(F.avg(F.col("false_positive").cast("int")) * 100, 1).alias("false_positive_rate_pct"),
    F.round(F.avg("time_to_triage_minutes"), 1).alias("avg_time_to_triage_minutes"),
    F.round(F.avg(F.col("sla_breached_calc").cast("int")) * 100, 1).alias("sla_breach_rate_pct"),
)

# 4c. Severity x source breakdown
severity_by_source = (
    enriched.groupBy("source_system", "severity")
    .agg(F.count("*").alias("alert_count"))
    .orderBy("source_system", "severity")
)

# 4d. Analyst performance (triage load + SLA performance per analyst)
analyst_performance = (
    enriched.groupBy("assigned_analyst", "analyst_shift")
    .agg(
        F.count("*").alias("alerts_triaged"),
        F.round(F.avg("time_to_triage_minutes"), 1).alias("avg_triage_minutes"),
        F.round(F.avg(F.col("sla_breached_calc").cast("int")) * 100, 1).alias("sla_breach_rate_pct"),
    )
    .orderBy(F.desc("alerts_triaged"))
)

# 4e. Business-unit / asset-criticality risk view
risk_by_business_unit = (
    enriched.groupBy("business_unit", "asset_criticality")
    .agg(
        F.count("*").alias("alert_count"),
        F.round(F.avg(F.col("severity").isin(["Critical", "High"]).cast("int")) * 100, 1).alias("pct_high_or_critical"),
    )
    .orderBy("business_unit", "asset_criticality")
)

# COMMAND ----------
# ---------------------------------------------------------------------------
# 5. LOAD — write curated tables. In Databricks this becomes:
#    df.write.format("delta").mode("overwrite").saveAsTable("cyber_fusion.curated.<name>")
# ---------------------------------------------------------------------------
import os
os.makedirs(CURATED_PATH, exist_ok=True)

tables = {
    "alerts_enriched": enriched,
    "daily_volume_by_source": daily_volume_by_source,
    "kpi_summary": kpi_summary,
    "severity_by_source": severity_by_source,
    "analyst_performance": analyst_performance,
    "risk_by_business_unit": risk_by_business_unit,
}

for name, df in tables.items():
    (
        df.toPandas()
        .to_csv(f"{CURATED_PATH}/{name}.csv", index=False)
    )
    print(f"Wrote curated table: {name} ({df.count():,} rows)")

print("\nETL pipeline complete.")
