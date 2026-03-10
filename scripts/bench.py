"""Benchmark Python capa vs Rust capa-rs: timing and rule coverage.

Single file mode:  python bench.py <sample> [outdir]
Directory mode:    python bench.py <directory> [outdir]

Single file dumps JSON results and a text report.
Directory mode processes all files and writes a CSV summary.
"""
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path

PYTHON_CAPA = os.environ.get("PYTHON_CAPA", "capa.exe")
RUST_CAPA = os.environ.get("RUST_CAPA", str(Path(__file__).resolve().parent.parent / "target" / "release" / "capa-rs.exe"))
RULES_DIR = os.environ.get("CAPA_RULES", str(Path(__file__).resolve().parent.parent / "capa-rules"))
SAMPLE_EXTENSIONS = {".exe", ".dll", ".sys", ".bin", ".scr", ".cpl", ".ocx", ""}
TIMING_PHASES_RUST = ["rules_ms", "extraction_ms", "matching_ms"]


def run_python_capa(sample, out_json):
    print(f"\n  Running Python capa...", flush=True)
    t0 = time.perf_counter()
    r = subprocess.run(
        [PYTHON_CAPA, "-j", str(sample)],
        capture_output=True, text=True,
    )
    wall = time.perf_counter() - t0
    if r.returncode != 0:
        print(f"  ERROR (exit {r.returncode}): {r.stderr[:200]}")
        return None, wall
    data = json.loads(r.stdout)
    out_json.write_text(r.stdout, encoding="utf-8")
    print(f"  Done in {wall:.1f}s -> {out_json}")
    return data, wall


def run_rust_capa(sample, out_json):
    print(f"\n  Running Rust capa-rs...", flush=True)
    t0 = time.perf_counter()
    r = subprocess.run(
        [RUST_CAPA, "-r", RULES_DIR, "-j", str(sample)],
        capture_output=True, text=True,
    )
    wall = time.perf_counter() - t0
    if r.returncode != 0:
        print(f"  ERROR (exit {r.returncode}): {r.stderr[:200]}")
        return None, wall
    data = json.loads(r.stdout)
    out_json.write_text(r.stdout, encoding="utf-8")
    print(f"  Done in {wall:.1f}s -> {out_json}")
    return data, wall


def python_rule_names(data):
    """Extract matched rule names from Python capa output."""
    return set(data.get("rules", {}).keys())


def rust_rule_names(data):
    """Extract matched rule names from Rust capa-rs output."""
    return {cap["name"] for cap in data.get("capabilities", [])}


def python_attack_ids(data):
    """Extract ATT&CK technique IDs from Python capa output."""
    ids = set()
    for rule in data.get("rules", {}).values():
        for entry in rule.get("meta", {}).get("attack", []):
            if isinstance(entry, dict):
                ids.add(entry.get("id", ""))
            elif isinstance(entry, list):
                for a in entry:
                    if isinstance(a, dict):
                        ids.add(a.get("id", ""))
    ids.discard("")
    return ids


def rust_attack_ids(data):
    """Extract ATT&CK technique IDs from Rust capa-rs output."""
    return set(data.get("mitre_attack", []))


def python_namespaces(data):
    """Extract rule namespaces from Python capa output."""
    ns = set()
    for rule in data.get("rules", {}).values():
        scope = rule.get("meta", {}).get("scopes", {})
        # namespace is in meta
        for entry in rule.get("meta", {}).get("attack", []):
            pass
    # Actually namespace is part of rule meta
    for name, rule in data.get("rules", {}).items():
        meta = rule.get("meta", {})
        if "maec" in meta and "analysis_conclusion" in meta["maec"]:
            ns.add(meta["maec"]["analysis_conclusion"])
    return ns


_SEP = "; "


def bench_single(sample, outdir):
    """Benchmark a single sample. Returns metrics or None on failure."""
    sample_path = Path(sample)
    sample_name = sample_path.stem if sample_path.suffix else sample_path.name
    print(f"\n{'='*62}")
    print(f"  Sample: {sample_path.name}")
    print(f"{'='*62}")

    outdir.mkdir(parents=True, exist_ok=True)

    pdata, pwall = run_python_capa(
        str(sample), outdir / f"{sample_name}_python.json"
    )
    rdata, rwall = run_rust_capa(
        str(sample), outdir / f"{sample_name}_rust.json"
    )

    if pdata is None or rdata is None:
        print("  SKIPPED (one or both tools failed)")
        return None

    # Rule names
    p_rules = python_rule_names(pdata)
    r_rules = rust_rule_names(rdata)
    shared_rules = p_rules & r_rules

    # ATT&CK IDs
    p_attack = python_attack_ids(pdata)
    r_attack = rust_attack_ids(rdata)
    shared_attack = p_attack & r_attack

    # Timing
    rust_timing = rdata.get("timing", {})
    rust_total_s = rust_timing.get("total_ms", 0) / 1000.0

    rule_coverage = len(shared_rules) / len(p_rules) * 100 if p_rules else 0
    attack_coverage = len(shared_attack) / len(p_attack) * 100 if p_attack else 0
    speedup = pwall / rwall if rwall > 0.001 else 0

    metrics = {
        "sample": sample_path.name,
        "python_wall": round(pwall, 2),
        "rust_wall": round(rwall, 2),
        "speedup": round(speedup, 1),
        "rust_rules_ms": rust_timing.get("rules_ms", 0),
        "rust_extraction_ms": rust_timing.get("extraction_ms", 0),
        "rust_matching_ms": rust_timing.get("matching_ms", 0),
        "rust_total_ms": rust_timing.get("total_ms", 0),
        "python_rules_matched": len(p_rules),
        "rust_rules_matched": len(r_rules),
        "shared_rules": len(shared_rules),
        "only_python_rules": _SEP.join(sorted(p_rules - r_rules)),
        "only_rust_rules": _SEP.join(sorted(r_rules - p_rules)),
        "rule_coverage_pct": round(rule_coverage, 1),
        "python_attack_ids": len(p_attack),
        "rust_attack_ids": len(r_attack),
        "shared_attack_ids": len(shared_attack),
        "only_python_attack": _SEP.join(sorted(p_attack - r_attack)),
        "only_rust_attack": _SEP.join(sorted(r_attack - p_attack)),
        "attack_coverage_pct": round(attack_coverage, 1),
    }

    # Build per-rule CSV rows
    all_rule_names = sorted(p_rules | r_rules)
    rule_rows = []
    for name in all_rule_names:
        in_python = name in p_rules
        in_rust = name in r_rules
        if in_python and in_rust:
            diff = "both"
        elif in_python:
            diff = "python_only"
        else:
            diff = "rust_only"
        rule_rows.append({
            "sample": sample_path.name,
            "rule": name,
            "diff": diff,
        })

    # Write per-sample rules CSV
    rules_csv_path = outdir / f"{sample_name}_rules.csv"
    with open(rules_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["sample", "rule", "diff"])
        writer.writeheader()
        writer.writerows(rule_rows)

    # Print report
    lines = []

    def out(s=""):
        print(s)
        lines.append(s)

    out(f"\n{'='*62}")
    out(f"  TIMING")
    out(f"{'='*62}")
    out(f"  {'Metric':<24} {'Value':>12}")
    out(f"  {'-'*40}")
    out(f"  {'Python wall clock':<24} {pwall:>11.2f}s")
    out(f"  {'Rust wall clock':<24} {rwall:>11.2f}s")
    out(f"  {'Speedup':<24} {speedup:>11.1f}x")
    out(f"  {'-'*40}")
    out(f"  {'Rust rule loading':<24} {rust_timing.get('rules_ms', 0):>9}ms")
    out(f"  {'Rust extraction':<24} {rust_timing.get('extraction_ms', 0):>9}ms")
    out(f"  {'Rust matching':<24} {rust_timing.get('matching_ms', 0):>9}ms")
    out(f"  {'Rust total':<24} {rust_timing.get('total_ms', 0):>9}ms")

    out(f"\n{'='*62}")
    out(f"  RULE COVERAGE")
    out(f"{'='*62}")
    out(f"  {'Metric':<24} {'Python':>8} {'Rust':>8} {'Shared':>8}")
    out(f"  {'-'*52}")
    out(f"  {'Rules matched':<24} {len(p_rules):8} {len(r_rules):8} {len(shared_rules):8}")
    out(f"  {'ATT&CK techniques':<24} {len(p_attack):8} {len(r_attack):8} {len(shared_attack):8}")
    out(f"\n  Only in Python:  {len(p_rules - r_rules)}")
    if p_rules - r_rules:
        for r in sorted(p_rules - r_rules):
            out(f"    - {r}")
    out(f"  Only in Rust:    {len(r_rules - p_rules)}")
    if r_rules - p_rules:
        for r in sorted(r_rules - p_rules):
            out(f"    + {r}")
    out(f"  Rule coverage:   {rule_coverage:.1f}%")
    out(f"  ATT&CK coverage: {attack_coverage:.1f}%")
    out()

    report_path = outdir / f"{sample_name}_bench.txt"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"  Report saved to: {report_path}")
    print(f"  Rules CSV:       {rules_csv_path}")

    return metrics, rule_rows


def bench_directory(directory, outdir):
    """Benchmark all binary files in a directory. Writes CSV summary."""
    sample_dir = Path(directory)
    outdir.mkdir(parents=True, exist_ok=True)

    samples = sorted(
        f for f in sample_dir.iterdir()
        if f.is_file() and (f.suffix.lower() in SAMPLE_EXTENSIONS)
    )

    if not samples:
        print(f"No sample files found in {sample_dir}")
        sys.exit(1)

    print(f"\nFound {len(samples)} samples in {sample_dir}")

    all_metrics = []
    all_rule_rows = []
    for i, sample in enumerate(samples, 1):
        print(f"\n[{i}/{len(samples)}] Processing {sample.name}...")
        result = bench_single(str(sample), outdir)
        if result:
            metrics, rule_rows = result
            all_metrics.append(metrics)
            all_rule_rows.extend(rule_rows)

    if not all_metrics:
        print("\nNo successful benchmarks.")
        sys.exit(1)

    # Write benchmark CSV
    csv_path = outdir / "benchmark_results.csv"
    fieldnames = list(all_metrics[0].keys())
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_metrics)

    # Write combined rules CSV
    rules_csv_path = outdir / "all_rules.csv"
    with open(rules_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["sample", "rule", "diff"])
        writer.writeheader()
        writer.writerows(all_rule_rows)

    print(f"\n{'='*62}")
    print(f"  DIRECTORY SUMMARY")
    print(f"{'='*62}")
    print(f"  Samples processed: {len(all_metrics)}/{len(samples)}")

    avg_speedup = sum(m["speedup"] for m in all_metrics) / len(all_metrics)
    avg_coverage = sum(m["rule_coverage_pct"] for m in all_metrics) / len(all_metrics)
    avg_attack = sum(m["attack_coverage_pct"] for m in all_metrics) / len(all_metrics)
    print(f"  Avg speedup:         {avg_speedup:.1f}x")
    print(f"  Avg rule coverage:   {avg_coverage:.1f}%")
    print(f"  Avg ATT&CK coverage: {avg_attack:.1f}%")
    print(f"\n  Benchmark CSV: {csv_path}")
    print(f"  Rules CSV:     {rules_csv_path}")


# ── Main ──
if len(sys.argv) < 2:
    print("Usage: python bench.py <sample_or_directory> [outdir]")
    sys.exit(1)

target = Path(sys.argv[1])
outdir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path.cwd()

if target.is_dir():
    bench_directory(target, outdir)
elif target.is_file():
    result = bench_single(str(target), outdir)
    if result is None:
        sys.exit(1)
    metrics, _ = result
    csv_path = outdir / "benchmark_results.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(metrics.keys()))
        writer.writeheader()
        writer.writerow(metrics)
    print(f"  Benchmark CSV:   {csv_path}")
else:
    print(f"Not found: {target}")
    sys.exit(1)
