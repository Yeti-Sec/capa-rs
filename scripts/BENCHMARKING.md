# Benchmarking Guide

Compares Python capa and Rust capa-rs output across timing, rule coverage, and ATT&CK technique detection.

## Running Benchmarks

```powershell
# Single sample
just bench "C:\path\to\sample.exe"

# Directory of samples
just bench "C:\path\to\samples\"

# Build first, then benchmark
just bench-full "C:\path\to\sample.exe"
```

Output files are written to the current working directory.

## Output Files

| Mode | File | Contents |
|------|------|----------|
| Both | `benchmark_results.csv` | Per-sample timing, counts, and diff values |
| Both | `{sample}_rules.csv` | Per-rule diff showing which tool matched each rule |
| Both | `{sample}_bench.txt` | Human-readable summary report |
| Both | `{sample}_python.json` | Raw Python capa JSON output |
| Both | `{sample}_rust.json` | Raw Rust capa-rs JSON output |
| Directory | `all_rules.csv` | Combined rules CSV across all samples |

---

## benchmark_results.csv

One row per sample. Columns are grouped into timing, rule counts, and diffs.

### Timing Columns

| Column | Meaning |
|--------|---------|
| `python_wall` | Wall-clock time for the Python capa subprocess (seconds) |
| `rust_wall` | Wall-clock time for the Rust capa-rs subprocess (seconds) |
| `speedup` | `python_wall / rust_wall` -- how many times faster Rust is |

Wall clock includes process startup overhead and rule loading.

### Rust Phase Timing Columns

Self-reported timing from capa-rs `timing` JSON field (milliseconds).

| Column | What it measures |
|--------|-----------------|
| `rust_rules_ms` | YAML rule parsing and compilation |
| `rust_extraction_ms` | Binary loading, disassembly, and feature extraction |
| `rust_matching_ms` | Rule matching against extracted features |
| `rust_total_ms` | Total analysis time |

### Rule Count Columns

| Column | Meaning |
|--------|---------|
| `python_rules_matched` | Number of rules Python capa matched |
| `rust_rules_matched` | Number of rules Rust capa-rs matched |
| `shared_rules` | Rules matched by both tools |
| `rule_coverage_pct` | `shared_rules / python_rules_matched * 100` |

### ATT&CK Columns

| Column | Meaning |
|--------|---------|
| `python_attack_ids` | Number of ATT&CK technique IDs from Python capa |
| `rust_attack_ids` | Number of ATT&CK technique IDs from Rust capa-rs |
| `shared_attack_ids` | Technique IDs found by both tools |
| `attack_coverage_pct` | `shared_attack_ids / python_attack_ids * 100` |

### Diff Columns (Actual Values)

These columns contain the actual rule names or ATT&CK IDs, semicolon-separated. They show what differs between the two tools.

| Column | Contents |
|--------|----------|
| `only_python_rules` | Rules matched by Python but not Rust |
| `only_rust_rules` | Rules matched by Rust but not Python |
| `only_python_attack` | ATT&CK IDs found by Python but not Rust |
| `only_rust_attack` | ATT&CK IDs found by Rust but not Python |

---

## Rules CSV ({sample}_rules.csv / all_rules.csv)

One row per unique rule name. Shows which tool matched each rule.

| Column | Values | Meaning |
|--------|--------|---------|
| `sample` | filename | Which sample this rule was matched against |
| `rule` | text | The rule name |
| `diff` | `both`, `python_only`, `rust_only` | Whether one or both tools matched this rule |

---

## Text Report ({sample}_bench.txt)

Human-readable summary printed to console and saved to file. Contains two sections:

- **TIMING** -- Wall-clock comparison and Rust internal phase breakdown
- **RULE COVERAGE** -- Rule and ATT&CK technique comparison with per-rule diffs

---

## Interpreting Results

### Rule coverage below 100%

Rules in `only_python_rules` that Rust missed. Filter the rules CSV to `diff=python_only` to see what's missing. Common causes:

- Different feature extraction depth (function discovery, string extraction)
- Unsupported rule features (certain matching operators or scopes)
- Different binary analysis backends (Python uses vivisect, Rust uses iced-x86)

### Rust-only rules

Rules in `only_rust_rules` that Python missed. This can happen when:

- Rust extracts more features from certain binary sections
- Different string encoding detection
- More aggressive function boundary detection

### ATT&CK coverage gaps

ATT&CK IDs track with rule coverage since techniques are derived from matched rules. Gaps here indicate the same underlying rule coverage issues.

### Speedup interpretation

The `speedup` column uses wall-clock time which includes process startup. For Python capa, startup includes Python interpreter initialization and vivisect loading. For Rust capa-rs, startup is minimal. The Rust internal timing (`rust_total_ms`) gives a more accurate picture of pure analysis time.
