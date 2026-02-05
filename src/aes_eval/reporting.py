"""Reporting functionality for AES evaluation.

Generates CSV, JSON, and Markdown reports from evaluation results.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .metrics import FullMetrics


def export_to_csv(
    metrics_list: list[FullMetrics],
    output_path: str | Path,
) -> Path:
    """Export metrics to CSV file.

    Args:
        metrics_list: List of FullMetrics from evaluations
        output_path: Path to output CSV file

    Returns:
        Path to written file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if not metrics_list:
        # Write empty file with headers
        with open(output_path, "w", newline="") as f:
            f.write("# No results\n")
        return output_path

    # Get all possible keys from first result
    flat_dicts = [m.to_flat_dict() for m in metrics_list]

    # Collect all keys across all results
    all_keys: set[str] = set()
    for d in flat_dicts:
        all_keys.update(d.keys())

    # Sort keys for consistent ordering
    fieldnames = sorted(all_keys, key=_sort_key)

    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for d in flat_dicts:
            writer.writerow(d)

    return output_path


def _sort_key(key: str) -> tuple[int, str]:
    """Sort key for CSV columns."""
    priority = {
        "technique": 0,
        "sbox_parallelism": 1,
        "mask_order_d": 2,
        "shares": 3,
        "correct": 4,
        "cycle_count_total": 5,
        "random_bits_total": 6,
        "latency_cycles": 7,
        "throughput_gbps": 8,
    }
    return (priority.get(key, 100), key)


def export_to_json(
    metrics_list: list[FullMetrics],
    output_path: str | Path,
    indent: int = 2,
) -> Path:
    """Export metrics to JSON file.

    Args:
        metrics_list: List of FullMetrics from evaluations
        output_path: Path to output JSON file
        indent: JSON indentation level

    Returns:
        Path to written file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    data = {
        "version": "1.0",
        "count": len(metrics_list),
        "results": [m.to_dict() for m in metrics_list],
    }

    with open(output_path, "w") as f:
        json.dump(data, f, indent=indent, default=str)

    return output_path


def export_to_markdown(
    metrics_list: list[FullMetrics],
    output_path: str | Path,
    title: str = "AES Evaluation Report",
) -> Path:
    """Export metrics to Markdown report.

    Args:
        metrics_list: List of FullMetrics from evaluations
        output_path: Path to output Markdown file
        title: Report title

    Returns:
        Path to written file
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines: list[str] = []

    # Header
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"Total configurations evaluated: {len(metrics_list)}")
    lines.append("")

    if not metrics_list:
        lines.append("No results to report.")
        with open(output_path, "w") as f:
            f.write("\n".join(lines))
        return output_path

    # Summary table
    lines.append("## Summary Table")
    lines.append("")

    # Create table header
    headers = [
        "Technique",
        "S-box Par.",
        "d",
        "Shares",
        "Correct",
        "Cycles",
        "Rand. Bits",
        "Latency (us)",
        "Tput (Gbps)",
        "Area Proxy",
    ]
    lines.append("| " + " | ".join(headers) + " |")
    lines.append("| " + " | ".join(["---"] * len(headers)) + " |")

    # Add rows
    for m in metrics_list:
        latency_us = m.performance.latency_seconds * 1e6
        row = [
            m.technique,
            str(m.sbox_parallelism),
            str(m.mask_order_d),
            str(m.shares),
            "Yes" if m.correct else "**NO**",
            str(m.cycle_count_total),
            str(m.random_bits_total),
            f"{latency_us:.3f}",
            f"{m.performance.throughput_gbps:.3f}",
            f"{m.area.composite_area_proxy:.1f}",
        ]
        lines.append("| " + " | ".join(row) + " |")

    lines.append("")

    # Cycle breakdown section
    lines.append("## Cycle Breakdown")
    lines.append("")
    lines.append("Average cycles per stage (across all configurations):")
    lines.append("")

    cycle_totals: dict[str, int] = {}
    for m in metrics_list:
        for k, v in m.cycle_breakdown.items():
            cycle_totals[k] = cycle_totals.get(k, 0) + v

    count = len(metrics_list)
    for stage, total in sorted(cycle_totals.items()):
        avg = total / count if count > 0 else 0
        lines.append(f"- **{stage}**: {avg:.1f} cycles (total: {total})")

    lines.append("")

    # Randomness section
    lines.append("## Randomness Consumption")
    lines.append("")

    random_totals: dict[str, int] = {}
    for m in metrics_list:
        for k, v in m.random_bits_breakdown.items():
            random_totals[k] = random_totals.get(k, 0) + v

    for category, total in sorted(random_totals.items()):
        avg = total / count if count > 0 else 0
        lines.append(f"- **{category}**: {avg:.1f} bits avg (total: {total})")

    lines.append("")

    # Performance comparison by technique
    lines.append("## Performance by Technique")
    lines.append("")

    techniques = sorted(set(m.technique for m in metrics_list))
    for tech in techniques:
        tech_metrics = [m for m in metrics_list if m.technique == tech]
        avg_cycles = sum(m.cycle_count_total for m in tech_metrics) / len(tech_metrics)
        avg_random = sum(m.random_bits_total for m in tech_metrics) / len(tech_metrics)
        avg_tput = sum(m.performance.throughput_gbps for m in tech_metrics) / len(tech_metrics)

        lines.append(f"### {tech}")
        lines.append(f"- Configurations: {len(tech_metrics)}")
        lines.append(f"- Avg cycles: {avg_cycles:.1f}")
        lines.append(f"- Avg random bits: {avg_random:.1f}")
        lines.append(f"- Avg throughput: {avg_tput:.3f} Gbps")
        lines.append("")

    # Warnings section
    all_warnings: list[str] = []
    for m in metrics_list:
        all_warnings.extend(m.warnings)

    if all_warnings:
        lines.append("## Warnings")
        lines.append("")
        unique_warnings = sorted(set(all_warnings))
        for w in unique_warnings:
            lines.append(f"- {w}")
        lines.append("")

    # Notes section
    lines.append("## Notes")
    lines.append("")
    lines.append("- All ciphertext outputs validated against PyCryptodome golden reference")
    lines.append("- Cycle counts based on S-box parallelism and round architecture model")
    lines.append("- Randomness estimates based on masking scheme literature (DOM, TI)")
    lines.append("- Area proxy is a relative metric; actual area depends on technology")
    lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    return output_path


def format_results_table(
    metrics_list: list[FullMetrics],
    compact: bool = False,
) -> str:
    """Format results as a table string for CLI output.

    Args:
        metrics_list: List of FullMetrics
        compact: Use compact format

    Returns:
        Formatted table string
    """
    try:
        from tabulate import tabulate
        use_tabulate = True
    except ImportError:
        use_tabulate = False

    if not metrics_list:
        return "No results."

    if compact:
        headers = ["Tech", "Par", "d", "OK", "Cycles", "Bits", "Gbps"]
        rows = [
            [
                m.technique[:12],
                m.sbox_parallelism,
                m.mask_order_d,
                "Y" if m.correct else "N",
                m.cycle_count_total,
                m.random_bits_total,
                f"{m.performance.throughput_gbps:.2f}",
            ]
            for m in metrics_list
        ]
    else:
        headers = ["Technique", "S-box Par", "d", "Shares", "Correct", "Cycles", "Random Bits", "Throughput (Gbps)"]
        rows = [
            [
                m.technique,
                m.sbox_parallelism,
                m.mask_order_d,
                m.shares,
                "Yes" if m.correct else "No",
                m.cycle_count_total,
                m.random_bits_total,
                f"{m.performance.throughput_gbps:.3f}",
            ]
            for m in metrics_list
        ]

    if use_tabulate:
        return tabulate(rows, headers=headers, tablefmt="simple")
    else:
        # Simple fallback table
        lines = []
        col_widths = [max(len(str(row[i])) for row in rows + [headers]) for i in range(len(headers))]

        header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
        lines.append(header_line)
        lines.append("-" * len(header_line))

        for row in rows:
            lines.append(" | ".join(str(v).ljust(col_widths[i]) for i, v in enumerate(row)))

        return "\n".join(lines)


def print_single_result(metrics: FullMetrics) -> str:
    """Format a single result for detailed output.

    Args:
        metrics: FullMetrics instance

    Returns:
        Formatted string
    """
    lines = [
        f"Technique: {metrics.technique}",
        f"Configuration: sbox_parallelism={metrics.sbox_parallelism}, d={metrics.mask_order_d}, shares={metrics.shares}",
        f"Round Architecture: {metrics.round_arch}",
        f"Clock Frequency: {metrics.f_clk_hz / 1e6:.1f} MHz",
        "",
        f"Correct: {'Yes' if metrics.correct else 'NO - MISMATCH'}",
        "",
        "Cycle Breakdown:",
    ]

    for stage, cycles in sorted(metrics.cycle_breakdown.items()):
        lines.append(f"  {stage}: {cycles}")
    lines.append(f"  TOTAL: {metrics.cycle_count_total}")

    lines.append("")
    lines.append("Randomness Breakdown:")
    for category, bits in sorted(metrics.random_bits_breakdown.items()):
        lines.append(f"  {category}: {bits} bits")
    lines.append(f"  TOTAL: {metrics.random_bits_total} bits")

    lines.append("")
    lines.append("Performance:")
    lines.append(f"  Latency: {metrics.performance.latency_cycles} cycles ({metrics.performance.latency_seconds * 1e6:.3f} us)")
    lines.append(f"  Throughput: {metrics.performance.throughput_gbps:.3f} Gbps")

    lines.append("")
    lines.append("Area Proxies:")
    lines.append(f"  S-box area: {metrics.area.sbox_area_proxy:.1f}")
    lines.append(f"  Register area: {metrics.area.register_area_proxy:.1f}")
    lines.append(f"  Composite: {metrics.area.composite_area_proxy:.1f}")

    if metrics.notes:
        lines.append("")
        lines.append("Notes:")
        for note in metrics.notes:
            lines.append(f"  - {note}")

    if metrics.warnings:
        lines.append("")
        lines.append("Warnings:")
        for warning in metrics.warnings:
            lines.append(f"  ! {warning}")

    return "\n".join(lines)
