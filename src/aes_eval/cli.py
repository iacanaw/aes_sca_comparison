"""Command-line interface for AES evaluation framework."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Sequence

import click

from .interfaces import EvalConfig, Result
from .golden import golden_encrypt, FIPS_197_TEST_VECTORS
from .cycle_models import create_cycle_model
from .randomness import RandomSource
from .implementations import TECHNIQUES, list_techniques, get_technique
from .metrics import calculate_full_metrics, FullMetrics
from .reporting import (
    export_to_csv,
    export_to_json,
    export_to_markdown,
    format_results_table,
    print_single_result,
)


@click.group()
@click.version_option(version="0.1.0", prog_name="aes-eval")
def main() -> None:
    """AES Side-Channel Resistant Implementation Evaluation Framework.

    Evaluate tradeoffs between AES implementations with different
    S-box parallelism and masking configurations.
    """
    pass


@main.command(name="list")
def list_cmd() -> None:
    """List available AES implementation techniques."""
    click.echo("Available techniques:")
    click.echo("")
    for tech in list_techniques():
        click.echo(f"  {tech['name']}")
        click.echo(f"    {tech['description']}")
        click.echo("")


@main.command()
@click.option(
    "--tech",
    type=str,
    required=True,
    help="Technique to validate (e.g., unmasked_baseline)",
)
@click.option(
    "--sbox-par",
    type=int,
    default=16,
    help="S-box parallelism (1-16, default: 16)",
)
@click.option(
    "--d",
    "mask_order_d",
    type=int,
    default=0,
    help="Masking order (0=unmasked, 1=2-share, 2=3-share, default: 0)",
)
@click.option(
    "--n",
    "num_tests",
    type=int,
    default=100,
    help="Number of random test vectors (default: 100)",
)
@click.option(
    "--f-clk",
    type=float,
    default=200e6,
    help="Clock frequency in Hz (default: 200e6)",
)
@click.option(
    "--seed",
    type=int,
    default=None,
    help="Random seed for reproducibility",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show detailed output",
)
def validate(
    tech: str,
    sbox_par: int,
    mask_order_d: int,
    num_tests: int,
    f_clk: float,
    seed: int | None,
    verbose: bool,
) -> None:
    """Validate a technique against FIPS-197 and random tests."""
    try:
        technique_cls = get_technique(tech)
    except KeyError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    config = EvalConfig(
        sbox_parallelism=sbox_par,
        mask_order_d=mask_order_d,
        f_clk_hz=f_clk,
    )

    technique = technique_cls()
    cycle_model = create_cycle_model(config.round_arch, config.sbox_parallelism)
    rng = RandomSource(seed=seed)

    click.echo(f"Validating: {tech}")
    click.echo(f"Config: sbox_parallelism={sbox_par}, d={mask_order_d}, shares={config.shares}")
    click.echo("")

    # FIPS-197 tests
    click.echo("Running FIPS-197 KAT tests...")
    fips_passed = 0
    fips_failed = 0

    for i, vec in enumerate(FIPS_197_TEST_VECTORS):
        rng.reset()
        cycle_model.reset()
        result = technique.encrypt_block(
            vec["key"],
            vec["plaintext"],
            rng,
            cycle_model,
            config,
        )
        if result.correct:
            fips_passed += 1
            if verbose:
                click.echo(f"  FIPS test {i+1}: PASS")
        else:
            fips_failed += 1
            click.echo(f"  FIPS test {i+1}: FAIL - {result.error_detail}")

    click.echo(f"FIPS-197 tests: {fips_passed}/{len(FIPS_197_TEST_VECTORS)} passed")

    # Random tests
    click.echo(f"\nRunning {num_tests} random tests...")

    import secrets
    if seed is not None:
        import random
        random.seed(seed)
        random_bytes = lambda n: bytes(random.randint(0, 255) for _ in range(n))
    else:
        random_bytes = secrets.token_bytes

    random_passed = 0
    random_failed = 0

    for i in range(num_tests):
        key = random_bytes(16)
        pt = random_bytes(16)

        rng.reset()
        cycle_model.reset()
        result = technique.encrypt_block(key, pt, rng, cycle_model, config)

        if result.correct:
            random_passed += 1
        else:
            random_failed += 1
            if verbose:
                click.echo(f"  Random test {i+1}: FAIL - {result.error_detail}")

    click.echo(f"Random tests: {random_passed}/{num_tests} passed")

    # Summary
    total_passed = fips_passed + random_passed
    total_tests = len(FIPS_197_TEST_VECTORS) + num_tests

    click.echo("")
    if total_passed == total_tests:
        click.echo(f"VALIDATION PASSED: All {total_tests} tests passed")
        sys.exit(0)
    else:
        click.echo(f"VALIDATION FAILED: {total_tests - total_passed} failures")
        sys.exit(1)


@main.command()
@click.option(
    "--tech",
    type=str,
    default="all",
    help="Techniques to evaluate (comma-separated or 'all', default: all)",
)
@click.option(
    "--sbox-par",
    type=str,
    default="1,5,16",
    help="S-box parallelism values (comma-separated, default: 1,5,16)",
)
@click.option(
    "--d",
    "mask_order_d_str",
    type=str,
    default="0,1,2",
    help="Masking orders (comma-separated, default: 0,1,2)",
)
@click.option(
    "--n",
    "num_tests",
    type=int,
    default=10,
    help="Tests per configuration (default: 10)",
)
@click.option(
    "--f-clk",
    type=float,
    default=200e6,
    help="Clock frequency in Hz (default: 200e6)",
)
@click.option(
    "--out",
    "output_dir",
    type=click.Path(),
    default="reports",
    help="Output directory (default: reports)",
)
@click.option(
    "--seed",
    type=int,
    default=42,
    help="Random seed for reproducibility (default: 42)",
)
def sweep(
    tech: str,
    sbox_par: str,
    mask_order_d_str: str,
    num_tests: int,
    f_clk: float,
    output_dir: str,
    seed: int,
) -> None:
    """Run parameter sweep across techniques and configurations."""
    # Parse techniques
    if tech == "all":
        techniques_to_run = list(TECHNIQUES.keys())
    else:
        techniques_to_run = [t.strip() for t in tech.split(",")]

    # Validate techniques
    for t in techniques_to_run:
        if t not in TECHNIQUES:
            click.echo(f"Error: Unknown technique '{t}'", err=True)
            click.echo(f"Available: {', '.join(TECHNIQUES.keys())}", err=True)
            sys.exit(1)

    # Parse parallelism values
    try:
        sbox_values = [int(x.strip()) for x in sbox_par.split(",")]
    except ValueError:
        click.echo(f"Error: Invalid sbox-par values: {sbox_par}", err=True)
        sys.exit(1)

    # Parse masking orders
    try:
        d_values = [int(x.strip()) for x in mask_order_d_str.split(",")]
    except ValueError:
        click.echo(f"Error: Invalid d values: {mask_order_d_str}", err=True)
        sys.exit(1)

    # Calculate total configurations
    total_configs = len(techniques_to_run) * len(sbox_values) * len(d_values)
    click.echo(f"Running sweep: {total_configs} configurations")
    click.echo(f"  Techniques: {', '.join(techniques_to_run)}")
    click.echo(f"  S-box parallelism: {sbox_values}")
    click.echo(f"  Masking orders (d): {d_values}")
    click.echo(f"  Tests per config: {num_tests}")
    click.echo("")

    all_metrics: list[FullMetrics] = []

    for tech_name in techniques_to_run:
        technique_cls = get_technique(tech_name)
        technique = technique_cls()

        for sbox_p in sbox_values:
            for d_val in d_values:
                config = EvalConfig(
                    sbox_parallelism=sbox_p,
                    mask_order_d=d_val,
                    f_clk_hz=f_clk,
                )

                cycle_model = create_cycle_model(config.round_arch, sbox_p)
                rng = RandomSource(seed=seed)

                # Run tests and collect average metrics
                results: list[Result] = []

                import random
                random.seed(seed)

                for _ in range(num_tests):
                    key = bytes(random.randint(0, 255) for _ in range(16))
                    pt = bytes(random.randint(0, 255) for _ in range(16))

                    rng.reset()
                    cycle_model.reset()
                    result = technique.encrypt_block(key, pt, rng, cycle_model, config)
                    results.append(result)

                # Use first result for metrics (they should be consistent)
                if results:
                    metrics = calculate_full_metrics(
                        results[0],
                        config,
                        tech_name,
                    )

                    # Check all results were correct
                    all_correct = all(r.correct for r in results)
                    if not all_correct:
                        metrics.correct = False
                        metrics.warnings.append(
                            f"Some tests failed: {sum(1 for r in results if r.correct)}/{len(results)} passed"
                        )

                    all_metrics.append(metrics)

                    status = "OK" if metrics.correct else "FAIL"
                    click.echo(
                        f"  {tech_name} sbox={sbox_p} d={d_val}: "
                        f"{status} cycles={metrics.cycle_count_total} "
                        f"random={metrics.random_bits_total}"
                    )

    # Export results
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    csv_path = export_to_csv(all_metrics, output_path / "summary.csv")
    json_path = export_to_json(all_metrics, output_path / "summary.json")
    md_path = export_to_markdown(all_metrics, output_path / "report.md")

    click.echo("")
    click.echo("Reports generated:")
    click.echo(f"  CSV:      {csv_path}")
    click.echo(f"  JSON:     {json_path}")
    click.echo(f"  Markdown: {md_path}")


@main.command()
@click.option(
    "--tech",
    type=str,
    required=True,
    help="Techniques to compare (comma-separated)",
)
@click.option(
    "--sbox-par",
    type=int,
    default=16,
    help="S-box parallelism (default: 16)",
)
@click.option(
    "--d",
    "mask_order_d",
    type=int,
    default=1,
    help="Masking order (default: 1)",
)
@click.option(
    "--n",
    "num_tests",
    type=int,
    default=100,
    help="Number of tests (default: 100)",
)
@click.option(
    "--f-clk",
    type=float,
    default=200e6,
    help="Clock frequency in Hz (default: 200e6)",
)
@click.option(
    "--seed",
    type=int,
    default=42,
    help="Random seed (default: 42)",
)
def compare(
    tech: str,
    sbox_par: int,
    mask_order_d: int,
    num_tests: int,
    f_clk: float,
    seed: int,
) -> None:
    """Compare multiple techniques with the same configuration."""
    techniques_to_compare = [t.strip() for t in tech.split(",")]

    # Validate
    for t in techniques_to_compare:
        if t not in TECHNIQUES:
            click.echo(f"Error: Unknown technique '{t}'", err=True)
            sys.exit(1)

    config = EvalConfig(
        sbox_parallelism=sbox_par,
        mask_order_d=mask_order_d,
        f_clk_hz=f_clk,
    )

    click.echo(f"Comparing techniques: {', '.join(techniques_to_compare)}")
    click.echo(f"Config: sbox_parallelism={sbox_par}, d={mask_order_d}, shares={config.shares}")
    click.echo(f"Running {num_tests} tests per technique...")
    click.echo("")

    all_metrics: list[FullMetrics] = []

    import random
    random.seed(seed)

    # Generate test vectors once
    test_vectors = [
        (bytes(random.randint(0, 255) for _ in range(16)),
         bytes(random.randint(0, 255) for _ in range(16)))
        for _ in range(num_tests)
    ]

    for tech_name in techniques_to_compare:
        technique_cls = get_technique(tech_name)
        technique = technique_cls()
        cycle_model = create_cycle_model(config.round_arch, sbox_par)
        rng = RandomSource(seed=seed)

        results: list[Result] = []
        for key, pt in test_vectors:
            rng.reset()
            cycle_model.reset()
            result = technique.encrypt_block(key, pt, rng, cycle_model, config)
            results.append(result)

        # Compute metrics from first result
        metrics = calculate_full_metrics(results[0], config, tech_name)
        all_correct = all(r.correct for r in results)
        metrics.correct = all_correct
        all_metrics.append(metrics)

    # Display comparison table
    click.echo(format_results_table(all_metrics))
    click.echo("")

    # Display detailed comparison
    click.echo("Detailed Comparison:")
    click.echo("-" * 60)

    for m in all_metrics:
        click.echo(f"\n{m.technique}:")
        click.echo(f"  Cycles: {m.cycle_count_total}")
        click.echo(f"  Random bits: {m.random_bits_total}")
        click.echo(f"  Throughput: {m.performance.throughput_gbps:.3f} Gbps")
        click.echo(f"  Latency: {m.performance.latency_seconds * 1e6:.3f} us")
        click.echo(f"  Area proxy: {m.area.composite_area_proxy:.1f}")

    # Relative comparison
    if len(all_metrics) >= 2:
        baseline = all_metrics[0]
        click.echo(f"\nRelative to {baseline.technique}:")
        for m in all_metrics[1:]:
            cycle_ratio = m.cycle_count_total / baseline.cycle_count_total if baseline.cycle_count_total else 0
            random_ratio = m.random_bits_total / baseline.random_bits_total if baseline.random_bits_total else 0
            click.echo(f"  {m.technique}:")
            click.echo(f"    Cycles: {cycle_ratio:.2f}x")
            if baseline.random_bits_total > 0:
                click.echo(f"    Random: {random_ratio:.2f}x")


if __name__ == "__main__":
    main()
