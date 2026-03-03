#!/usr/bin/env python3
"""
Security Gate Metrics Collector
Book Reference: Chapter 3, Section 3.2.1.3

PURPOSE:
    Aggregates scan results collected during the learning phase (weeks 1-2)
    to help teams set realistic thresholds before moving to enforcement mode.

    Answers the key questions from Section 3.2.1.3:
      - What is our current security baseline?
      - What is our false positive rate?
      - What are realistic thresholds for our codebase?
      - Are we trending better or worse over time?

USAGE:
    # Analyze artifacts downloaded from GitHub Actions
    python metrics-collector.py --artifacts-dir ./artifacts

    # Analyze a single scan result
    python metrics-collector.py --sast sast-results.json

    # Analyze with Trivy results
    python metrics-collector.py \\
        --sast sast-results.json \\
        --trivy trivy-results.json

    # Generate threshold recommendations
    python metrics-collector.py \\
        --artifacts-dir ./artifacts \\
        --recommend-thresholds

    # Export metrics as JSON for dashboards
    python metrics-collector.py \\
        --artifacts-dir ./artifacts \\
        --output metrics-report.json

    # Compare two time periods (trend analysis)
    python metrics-collector.py \\
        --artifacts-dir ./artifacts \\
        --compare-weeks 2

REQUIREMENTS:
    pip install rich click    # Optional - falls back to plain output
"""

import json
import os
import sys
import argparse
import statistics
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Optional rich output - falls back gracefully if not installed
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import print as rprint
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None


# =============================================================================
# Data Models
# =============================================================================

@dataclass
class ScanMetrics:
    """Metrics from a single scan run."""
    date:          str
    branch:        str
    commit:        str
    phase:         str = "unknown"

    # SAST counts
    sast_critical:     int = 0
    sast_high:         int = 0
    sast_medium:       int = 0
    sast_low:          int = 0
    sast_total:        int = 0
    sast_unique_rules: int = 0

    # Dependency counts
    dep_critical: int = 0
    dep_high:     int = 0
    dep_medium:   int = 0
    dep_low:      int = 0

    # Rule breakdown (for false positive analysis)
    sast_rules_fired: dict = field(default_factory=dict)

    # Dependency breakdown
    dep_packages_affected: list = field(default_factory=list)


@dataclass
class ThresholdRecommendation:
    """
    Recommended thresholds based on collected metrics.
    Implements the Table 3.4 philosophy with data-driven values.
    """
    sast_critical: int
    sast_high:     int
    sast_medium:   int
    dep_critical:  int
    dep_high:      int
    dep_medium:    int

    # Confidence in the recommendation
    confidence:    str    = "medium"    # low | medium | high
    sample_size:   int    = 0
    reasoning:     dict   = field(default_factory=dict)


@dataclass
class TrendAnalysis:
    """Week-over-week trend for a severity level."""
    severity:       str
    scanner:        str
    week1_avg:      float
    week2_avg:      float
    trend:          str     # improving | worsening | stable
    pct_change:     float


# =============================================================================
# Parsers
# =============================================================================

class SemgrepParser:
    """Parse Semgrep JSON output into ScanMetrics."""

    @staticmethod
    def parse(file_path: str,
              date: str = "",
              branch: str = "",
              commit: str = "") -> ScanMetrics:
        """
        Parse a Semgrep JSON results file.

        Args:
            file_path: Path to semgrep JSON output
            date:      Scan date (ISO format)
            branch:    Git branch name
            commit:    Git commit SHA

        Returns:
            ScanMetrics populated from the file
        """
        with open(file_path) as f:
            data = json.load(f)

        results = data.get("results", [])

        metrics = ScanMetrics(
            date   = date or datetime.now(timezone.utc).isoformat(),
            branch = branch,
            commit = commit,
        )

        # Count by severity
        rules_fired = Counter()
        for result in results:
            severity = result.get("extra", {}).get("severity", "").upper()
            rule_id  = result.get("check_id", "unknown")
            rules_fired[rule_id] += 1

            if severity == "ERROR":
                metrics.sast_critical += 1
            elif severity == "WARNING":
                metrics.sast_high += 1
            elif severity == "INFO":
                metrics.sast_medium += 1
            else:
                metrics.sast_low += 1

        metrics.sast_total        = len(results)
        metrics.sast_unique_rules = len(rules_fired)
        metrics.sast_rules_fired  = dict(rules_fired.most_common(20))

        return metrics


class TrivyParser:
    """Parse Trivy JSON output and merge into ScanMetrics."""

    @staticmethod
    def merge(metrics: ScanMetrics, file_path: str) -> ScanMetrics:
        """
        Parse a Trivy JSON results file and merge into existing metrics.

        Args:
            metrics:   Existing ScanMetrics to merge into
            file_path: Path to Trivy JSON output

        Returns:
            Updated ScanMetrics with dependency findings added
        """
        with open(file_path) as f:
            data = json.load(f)

        packages_affected = set()

        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities") or []:
                severity = vuln.get("Severity", "").upper()
                pkg_name = vuln.get("PkgName", "unknown")
                packages_affected.add(pkg_name)

                if severity == "CRITICAL":
                    metrics.dep_critical += 1
                elif severity == "HIGH":
                    metrics.dep_high += 1
                elif severity == "MEDIUM":
                    metrics.dep_medium += 1
                else:
                    metrics.dep_low += 1

        metrics.dep_packages_affected = list(packages_affected)
        return metrics


class ArtifactLoader:
    """
    Load scan metrics from a directory of GitHub Actions artifacts.

    Expects artifacts downloaded from GitHub Actions in the format:
        artifacts/
            learning-mode-<run>-<sha>/
                daily-metrics.json      (pre-computed metrics)
                sast-results.json       (raw Semgrep output)
                trivy-results.json      (raw Trivy output)
    """

    def __init__(self, artifacts_dir: str):
        self.artifacts_dir = Path(artifacts_dir)

    def load_all(self) -> list[ScanMetrics]:
        """
        Load all scan metrics from the artifacts directory.

        Returns:
            List of ScanMetrics sorted by date
        """
        all_metrics = []

        for artifact_dir in sorted(self.artifacts_dir.iterdir()):
            if not artifact_dir.is_dir():
                continue

            metrics = self._load_artifact(artifact_dir)
            if metrics:
                all_metrics.append(metrics)

        # Sort by date
        all_metrics.sort(key=lambda m: m.date)
        return all_metrics

    def _load_artifact(self, artifact_dir: Path) -> Optional[ScanMetrics]:
        """Load metrics from a single artifact directory."""

        # Try pre-computed metrics first (from learning mode workflow)
        metrics_file = artifact_dir / "daily-metrics.json"
        if metrics_file.exists():
            try:
                with open(metrics_file) as f:
                    data = json.load(f)

                metrics = ScanMetrics(
                    date   = data.get("date", ""),
                    branch = data.get("branch", ""),
                    commit = data.get("commit", ""),
                    phase  = data.get("phase", "unknown"),
                )

                sast = data.get("sast", {})
                metrics.sast_critical     = sast.get("critical",     0)
                metrics.sast_high         = sast.get("high",         0)
                metrics.sast_medium       = sast.get("medium",       0)
                metrics.sast_low          = sast.get("low",          0)
                metrics.sast_total        = sast.get("total",        0)
                metrics.sast_unique_rules = sast.get("unique_rules", 0)

                dep = data.get("dependencies", {})
                metrics.dep_critical = dep.get("critical", 0)
                metrics.dep_high     = dep.get("high",     0)
                metrics.dep_medium   = dep.get("medium",   0)

                return metrics

            except (json.JSONDecodeError, KeyError):
                pass

        # Fall back to parsing raw scan files
        sast_file  = artifact_dir / "sast-results.json"
        trivy_file = artifact_dir / "trivy-results.json"

        if sast_file.exists():
            try:
                metrics = SemgrepParser.parse(str(sast_file))
                if trivy_file.exists():
                    metrics = TrivyParser.merge(metrics, str(trivy_file))
                return metrics
            except (json.JSONDecodeError, KeyError):
                pass

        return None


# =============================================================================
# Analysis Engine
# =============================================================================

class MetricsAnalyzer:
    """
    Analyzes collected scan metrics to produce:
      - Baseline statistics
      - Threshold recommendations
      - Trend analysis
      - False positive indicators
    """

    def __init__(self, metrics: list[ScanMetrics]):
        self.metrics = metrics

    def baseline_stats(self) -> dict:
        """
        Calculate baseline statistics across all scans.
        Used to understand the starting point before enforcement.
        """
        if not self.metrics:
            return {}

        def stats_for(values: list[int]) -> dict:
            if not values:
                return {"min": 0, "max": 0, "mean": 0.0,
                        "median": 0.0, "p90": 0.0}
            sorted_vals = sorted(values)
            p90_idx     = int(len(sorted_vals) * 0.9)
            return {
                "min":    min(values),
                "max":    max(values),
                "mean":   round(statistics.mean(values), 1),
                "median": statistics.median(values),
                "p90":    sorted_vals[p90_idx],
            }

        return {
            "sample_size":    len(self.metrics),
            "date_range": {
                "start": self.metrics[0].date  if self.metrics else "",
                "end":   self.metrics[-1].date if self.metrics else "",
            },
            "sast": {
                "critical": stats_for([m.sast_critical for m in self.metrics]),
                "high":     stats_for([m.sast_high     for m in self.metrics]),
                "medium":   stats_for([m.sast_medium   for m in self.metrics]),
            },
            "dependencies": {
                "critical": stats_for([m.dep_critical for m in self.metrics]),
                "high":     stats_for([m.dep_high     for m in self.metrics]),
                "medium":   stats_for([m.dep_medium   for m in self.metrics]),
            },
        }

    def recommend_thresholds(self) -> ThresholdRecommendation:
        """
        Recommend thresholds based on collected baseline data.

        Strategy (implements Section 3.2.1.3 philosophy):
          - Critical: Always 0 (no exceptions per Table 3.4)
          - High:     90th percentile of observed values + 20% buffer
          - Medium:   90th percentile + 50% buffer (warn only)
          - Low:      Ignored per Table 3.4

        The 90th percentile approach means the gate will pass 90% of
        historical builds, giving the team room to improve gradually.
        """
        if not self.metrics:
            # Return Table 3.4 defaults if no data
            return ThresholdRecommendation(
                sast_critical = 0,
                sast_high     = 3,
                sast_medium   = 10,
                dep_critical  = 0,
                dep_high      = 5,
                dep_medium    = 20,
                confidence    = "low",
                sample_size   = 0,
                reasoning     = {"note": "No data - using Table 3.4 defaults"},
            )

        def p90_with_buffer(values: list[int],
                            buffer_pct: float = 0.2) -> int:
            """90th percentile + buffer, rounded up to nearest integer."""
            if not values or max(values) == 0:
                return 0
            sorted_vals = sorted(values)
            p90_idx     = int(len(sorted_vals) * 0.9)
            p90         = sorted_vals[p90_idx]
            return max(0, int(p90 * (1 + buffer_pct)) + 1)

        sast_high_values = [m.sast_high   for m in self.metrics]
        sast_med_values  = [m.sast_medium for m in self.metrics]
        dep_high_values  = [m.dep_high    for m in self.metrics]
        dep_med_values   = [m.dep_medium  for m in self.metrics]

        # Confidence based on sample size
        n = len(self.metrics)
        if n >= 20:
            confidence = "high"
        elif n >= 10:
            confidence = "medium"
        else:
            confidence = "low"

        rec = ThresholdRecommendation(
            sast_critical = 0,    # Always 0 per Table 3.4
            sast_high     = p90_with_buffer(sast_high_values, 0.20),
            sast_medium   = p90_with_buffer(sast_med_values,  0.50),
            dep_critical  = 0,    # Always 0 per Table 3.4
            dep_high      = p90_with_buffer(dep_high_values,  0.20),
            dep_medium    = p90_with_buffer(dep_med_values,   0.50),
            confidence    = confidence,
            sample_size   = n,
            reasoning     = {
                "method":      "90th percentile + buffer",
                "sast_high":   f"p90={sorted(sast_high_values)[int(n*0.9)]} + 20% buffer",
                "dep_high":    f"p90={sorted(dep_high_values)[int(n*0.9)]} + 20% buffer",
                "critical":    "Always 0 per Table 3.4 - no exceptions",
                "note":        f"Based on {n} scans. "
                               f"{'High confidence.' if confidence == 'high' else 'Collect more data for higher confidence.'}",
            },
        )

        return rec

    def trend_analysis(self,
                       compare_weeks: int = 2) -> list[TrendAnalysis]:
        """
        Analyze week-over-week trends.

        Args:
            compare_weeks: Number of weeks to compare

        Returns:
            List of TrendAnalysis for each severity/scanner combination
        """
        if len(self.metrics) < 2:
            return []

        trends = []

        # Split metrics into two halves for comparison
        mid   = len(self.metrics) // 2
        first = self.metrics[:mid]
        last  = self.metrics[mid:]

        comparisons = [
            ("critical", "sast",         "sast_critical"),
            ("high",     "sast",         "sast_high"),
            ("medium",   "sast",         "sast_medium"),
            ("critical", "dependencies", "dep_critical"),
            ("high",     "dependencies", "dep_high"),
        ]

        for severity, scanner, attr in comparisons:
            first_vals = [getattr(m, attr) for m in first]
            last_vals  = [getattr(m, attr) for m in last]

            first_avg = statistics.mean(first_vals) if first_vals else 0
            last_avg  = statistics.mean(last_vals)  if last_vals  else 0

            if first_avg == 0:
                pct_change = 0.0
            else:
                pct_change = ((last_avg - first_avg) / first_avg) * 100

            if pct_change < -10:
                trend = "improving"
            elif pct_change > 10:
                trend = "worsening"
            else:
                trend = "stable"

            trends.append(TrendAnalysis(
                severity   = severity,
                scanner    = scanner,
                week1_avg  = round(first_avg, 1),
                week2_avg  = round(last_avg,  1),
                trend      = trend,
                pct_change = round(pct_change, 1),
            ))

        return trends

    def false_positive_indicators(self) -> dict:
        """
        Identify potential false positive patterns.

        High-frequency rules that fire on every scan are candidates
        for false positive review or suppression.
        """
        if not self.metrics:
            return {}

        # Aggregate rule frequencies across all scans
        all_rules: Counter = Counter()
        for m in self.metrics:
            all_rules.update(m.sast_rules_fired)

        total_scans = len(self.metrics)

        # Rules that fire in > 80% of scans are likely false positives
        # or low-value rules worth reviewing
        high_frequency = {
            rule: {
                "total_fires":    count,
                "avg_per_scan":   round(count / total_scans, 1),
                "fire_rate_pct":  round(
                    sum(1 for m in self.metrics
                        if rule in m.sast_rules_fired) / total_scans * 100,
                    1
                ),
            }
            for rule, count in all_rules.most_common(10)
        }

        # Rules that fire in > 80% of scans
        likely_fp_candidates = {
            rule: data
            for rule, data in high_frequency.items()
            if data["fire_rate_pct"] > 80
        }

        return {
            "total_scans":          total_scans,
            "total_unique_rules":   len(all_rules),
            "top_10_rules":         high_frequency,
            "likely_fp_candidates": likely_fp_candidates,
            "recommendation": (
                f"Review {len(likely_fp_candidates)} rule(s) that fire in "
                f">80% of scans. Consider suppressing with "
                f"'# nosemgrep: rule-id' if confirmed false positives."
                if likely_fp_candidates
                else "No obvious false positive patterns detected."
            ),
        }

    def readiness_assessment(self) -> dict:
        """
        Assess readiness to move to the next phase.

        Returns a checklist matching Section 3.2.1.3 criteria.
        """
        if not self.metrics:
            return {"ready": False, "reason": "No data collected yet"}

        stats = self.baseline_stats()
        trends = self.trend_analysis()
        fp_indicators = self.false_positive_indicators()

        recent = self.metrics[-5:] if len(self.metrics) >= 5 else self.metrics

        # Check criteria for moving from learning -> warning
        learning_to_warning = {
            "sufficient_data": {
                "met":   len(self.metrics) >= 10,
                "value": len(self.metrics),
                "target": "10+ scans",
                "note":  "Need enough data to understand baseline",
            },
            "false_positives_reviewed": {
                "met":   len(fp_indicators.get("likely_fp_candidates", {})) == 0,
                "value": len(fp_indicators.get("likely_fp_candidates", {})),
                "target": "0 unreviewed FP candidates",
                "note":  "Review high-frequency rules before enforcing",
            },
            "critical_findings_understood": {
                "met":   stats["sast"]["critical"]["max"] < 10,
                "value": stats["sast"]["critical"]["max"],
                "target": "< 10 max critical",
                "note":  "Understand what critical findings exist",
            },
        }

        # Check criteria for moving from warning -> enforcement
        warning_to_enforcement = {
            "zero_recent_criticals": {
                "met":   all(m.sast_critical == 0 and
                             m.dep_critical  == 0
                             for m in recent),
                "value": max((m.sast_critical + m.dep_critical)
                             for m in recent),
                "target": "0 critical in last 5 builds",
                "note":  "Team must be able to keep criticals at zero",
            },
            "high_trending_down": {
                "met":   any(t.trend == "improving"
                             for t in trends
                             if t.severity == "high"),
                "value": next(
                    (f"{t.pct_change}%" for t in trends
                     if t.severity == "high" and t.scanner == "sast"),
                    "unknown"
                ),
                "target": "High findings trending down",
                "note":  "Team should be actively fixing high findings",
            },
            "team_trained": {
                "met":   False,    # Manual check - cannot be automated
                "value": "Manual verification required",
                "target": "Team knows how to fix common finding types",
                "note":  "Verify team has reviewed findings and knows fixes",
            },
        }

        l_to_w_ready = all(
            v["met"] for v in learning_to_warning.values()
        )
        w_to_e_ready = all(
            v["met"] for v in warning_to_enforcement.values()
        )

        return {
            "sample_size":             len(self.metrics),
            "learning_to_warning": {
                "ready":    l_to_w_ready,
                "criteria": learning_to_warning,
            },
            "warning_to_enforcement": {
                "ready":    w_to_e_ready,
                "criteria": warning_to_enforcement,
            },
        }


# =============================================================================
# Report Generator
# =============================================================================

class MetricsReporter:
    """Generates human-readable reports from metrics analysis."""

    def __init__(self, analyzer: MetricsAnalyzer):
        self.analyzer = analyzer

    def print_full_report(self, recommend: bool = False) -> None:
        """Print a complete metrics report to the console."""

        stats    = self.analyzer.baseline_stats()
        fp_data  = self.analyzer.false_positive_indicators()
        trends   = self.analyzer.trend_analysis()
        readiness = self.analyzer.readiness_assessment()

        if RICH_AVAILABLE:
            self._print_rich(stats, fp_data, trends, readiness, recommend)
        else:
            self._print_plain(stats, fp_data, trends, readiness, recommend)

    def _print_rich(self, stats, fp_data, trends,
                    readiness, recommend) -> None:
        """Rich formatted output."""

        console.print(Panel.fit(
            "[bold]Security Gate Metrics Report[/bold]\n"
            f"Samples: {stats.get('sample_size', 0)} | "
            f"Period: {stats.get('date_range', {}).get('start', 'N/A')} → "
            f"{stats.get('date_range', {}).get('end', 'N/A')}",
            style="blue"
        ))

        # Baseline stats table
        table = Table(title="Baseline Statistics", show_header=True)
        table.add_column("Scanner",  style="cyan")
        table.add_column("Severity", style="white")
        table.add_column("Min",      justify="right")
        table.add_column("Mean",     justify="right")
        table.add_column("Median",   justify="right")
        table.add_column("P90",      justify="right")
        table.add_column("Max",      justify="right")

        for scanner, sev_key in [("SAST", "sast"),
                                  ("Dependencies", "dependencies")]:
            for sev in ["critical", "high", "medium"]:
                s = stats.get(sev_key, {}).get(sev, {})
                color = ("red" if sev == "critical"
                         else "yellow" if sev == "high"
                         else "white")
                table.add_row(
                    scanner, sev,
                    f"[{color}]{s.get('min', 0)}[/{color}]",
                    f"[{color}]{s.get('mean', 0)}[/{color}]",
                    f"[{color}]{s.get('median', 0)}[/{color}]",
                    f"[{color}]{s.get('p90', 0)}[/{color}]",
                    f"[{color}]{s.get('max', 0)}[/{color}]",
                )

        console.print(table)

        # Trend analysis
        if trends:
            trend_table = Table(title="Trend Analysis", show_header=True)
            trend_table.add_column("Scanner")
            trend_table.add_column("Severity")
            trend_table.add_column("Period 1 Avg", justify="right")
            trend_table.add_column("Period 2 Avg", justify="right")
            trend_table.add_column("Change",       justify="right")
            trend_table.add_column("Trend")

            for t in trends:
                trend_icon  = ("✅" if t.trend == "improving"
                               else "❌" if t.trend == "worsening"
                               else "➡️")
                trend_color = ("green" if t.trend == "improving"
                               else "red" if t.trend == "worsening"
                               else "yellow")
                trend_table.add_row(
                    t.scanner, t.severity,
                    str(t.week1_avg),
                    str(t.week2_avg),
                    f"[{trend_color}]{t.pct_change:+.1f}%[/{trend_color}]",
                    f"[{trend_color}]{trend_icon} {t.trend}[/{trend_color}]",
                )

            console.print(trend_table)

        # Threshold recommendations
        if recommend:
            rec = self.analyzer.recommend_thresholds()
            console.print(Panel(
                f"[bold]Recommended Thresholds[/bold] "
                f"(confidence: {rec.confidence}, "
                f"based on {rec.sample_size} scans)\n\n"
                f"[yellow]# .security/thresholds.yml[/yellow]\n"
                f"sast:\n"
                f"  critical: {rec.sast_critical}   "
                f"[dim]# Always 0 per Table 3.4[/dim]\n"
                f"  high:     {rec.sast_high}   "
                f"[dim]# {rec.reasoning.get('sast_high', '')}[/dim]\n"
                f"  medium:   {rec.sast_medium}  "
                f"[dim]# Warn only[/dim]\n"
                f"  low:      ignore\n\n"
                f"dependencies:\n"
                f"  critical: {rec.dep_critical}   "
                f"[dim]# Always 0 per Table 3.4[/dim]\n"
                f"  high:     {rec.dep_high}   "
                f"[dim]# {rec.reasoning.get('dep_high', '')}[/dim]\n"
                f"  medium:   {rec.dep_medium}  "
                f"[dim]# Warn only[/dim]\n"
                f"  low:      ignore",
                title="Threshold Recommendations",
                style="green"
            ))

        # Readiness assessment
        console.print("\n[bold]Phase Transition Readiness[/bold]\n")

        for phase, key in [
            ("Learning → Warning (Week 3-4)",   "learning_to_warning"),
            ("Warning → Enforcement (Week 5+)", "warning_to_enforcement"),
        ]:
            phase_data = readiness.get(key, {})
            ready      = phase_data.get("ready", False)
            icon       = "✅" if ready else "❌"
            color      = "green" if ready else "red"

            console.print(
                f"  [{color}]{icon} {phase}: "
                f"{'READY' if ready else 'NOT READY'}[/{color}]"
            )

            for criterion, data in phase_data.get("criteria", {}).items():
                met   = data.get("met", False)
                c_icon = "✅" if met else "❌"
                c_color = "green" if met else "red"
                console.print(
                    f"    [{c_color}]{c_icon}[/{c_color}] "
                    f"{criterion}: {data.get('value', 'N/A')} "
                    f"(target: {data.get('target', 'N/A')})"
                )
            console.print()

    def _print_plain(self, stats, fp_data, trends,
                     readiness, recommend) -> None:
        """Plain text fallback output."""

        print("\n" + "=" * 60)
        print("  Security Gate Metrics Report")
        print("=" * 60)
        print(f"  Samples : {stats.get('sample_size', 0)}")
        dr = stats.get('date_range', {})
        print(f"  Period  : {dr.get('start', 'N/A')} → {dr.get('end', 'N/A')}")
        print("-" * 60)

        print("\n  Baseline Statistics:\n")
        for scanner, sev_key in [("SAST", "sast"),
                                  ("Dependencies", "dependencies")]:
            print(f"  {scanner}:")
            for sev in ["critical", "high", "medium"]:
                s = stats.get(sev_key, {}).get(sev, {})
                print(
                    f"    {sev:10s}: "
                    f"min={s.get('min',0):3d}  "
                    f"mean={s.get('mean',0):5.1f}  "
                    f"p90={s.get('p90',0):3d}  "
                    f"max={s.get('max',0):3d}"
                )

        if trends:
            print("\n  Trend Analysis:\n")
            for t in trends:
                icon = ("↓" if t.trend == "improving"
                        else "↑" if t.trend == "worsening"
                        else "→")
                print(
                    f"  {t.scanner:15s} {t.severity:10s}: "
                    f"{t.week1_avg:5.1f} → {t.week2_avg:5.1f} "
                    f"({t.pct_change:+.1f}%) {icon} {t.trend}"
                )

        if recommend:
            rec = self.analyzer.recommend_thresholds()
            print(f"\n  Recommended Thresholds "
                  f"(confidence: {rec.confidence}, "
                  f"n={rec.sample_size}):\n")
            print("  # .security/thresholds.yml")
            print("  sast:")
            print(f"    critical: {rec.sast_critical}   # Always 0")
            print(f"    high:     {rec.sast_high}")
            print(f"    medium:   {rec.sast_medium}")
            print("    low:      ignore")
            print("  dependencies:")
            print(f"    critical: {rec.dep_critical}   # Always 0")
            print(f"    high:     {rec.dep_high}")
            print(f"    medium:   {rec.dep_medium}")
            print("    low:      ignore")

        print("\n  Phase Transition Readiness:\n")
        for phase, key in [
            ("Learning → Warning",   "learning_to_warning"),
            ("Warning → Enforcement","warning_to_enforcement"),
        ]:
            phase_data = readiness.get(key, {})
            ready      = phase_data.get("ready", False)
            print(f"  {'✅' if ready else '❌'} {phase}: "
                  f"{'READY' if ready else 'NOT READY'}")
            for criterion, data in phase_data.get("criteria", {}).items():
                met = data.get("met", False)
                print(f"    {'✅' if met else '❌'} {criterion}: "
                      f"{data.get('value', 'N/A')} "
                      f"(target: {data.get('target', 'N/A')})")
            print()

    def save_json(self, output_path: str) -> None:
        """Save full metrics report as JSON for dashboards."""
        report = {
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "baseline_stats":  self.analyzer.baseline_stats(),
            "trends":          [asdict(t) for t in
                                self.analyzer.trend_analysis()],
            "thresholds":      asdict(
                                self.analyzer.recommend_thresholds()),
            "false_positives": self.analyzer.false_positive_indicators(),
            "readiness":       self.analyzer.readiness_assessment(),
        }

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n  📄 Metrics report saved to: {output_path}")


# =============================================================================
# CLI Entry Point
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Security Gate Metrics Collector - Chapter 3, Section 3.2.1.3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze artifacts from learning mode
  python metrics-collector.py --artifacts-dir ./artifacts

  # Analyze single scan files
  python metrics-collector.py \\
    --sast sast-results.json \\
    --trivy trivy-results.json

  # Get threshold recommendations
  python metrics-collector.py \\
    --artifacts-dir ./artifacts \\
    --recommend-thresholds

  # Export for dashboards
  python metrics-collector.py \\
    --artifacts-dir ./artifacts \\
    --output metrics-report.json
        """,
    )

    parser.add_argument(
        "--artifacts-dir",
        help="Directory containing downloaded GitHub Actions artifacts",
    )
    parser.add_argument(
        "--sast",
        help="Path to Semgrep JSON results file",
    )
    parser.add_argument(
        "--trivy",
        help="Path to Trivy JSON results file",
    )
    parser.add_argument(
        "--recommend-thresholds",
        action="store_true",
        help="Generate threshold recommendations based on collected data",
    )
    parser.add_argument(
        "--compare-weeks",
        type=int,
        default=2,
        help="Number of weeks to compare for trend analysis (default: 2)",
    )
    parser.add_argument(
        "--output",
        help="Save JSON report to this path",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # Load metrics
    all_metrics: list[ScanMetrics] = []

    if args.artifacts_dir:
        loader      = ArtifactLoader(args.artifacts_dir)
        all_metrics = loader.load_all()
        print(f"Loaded {len(all_metrics)} scan(s) from {args.artifacts_dir}")

    elif args.sast:
        metrics = SemgrepParser.parse(
            args.sast,
            date   = datetime.now(timezone.utc).isoformat(),
            branch = os.environ.get("GITHUB_REF_NAME", "unknown"),
            commit = os.environ.get("GITHUB_SHA", "unknown"),
        )
        if args.trivy:
            metrics = TrivyParser.merge(metrics, args.trivy)
        all_metrics = [metrics]

    else:
        print("Error: provide --artifacts-dir or --sast")
        sys.exit(1)

    if not all_metrics:
        print("No metrics found. Check your artifacts directory.")
        sys.exit(1)

    # Analyze and report
    analyzer = MetricsAnalyzer(all_metrics)
    reporter = MetricsReporter(analyzer)

    reporter.print_full_report(recommend=args.recommend_thresholds)

    if args.output:
        reporter.save_json(args.output)


if __name__ == "__main__":
    main()
