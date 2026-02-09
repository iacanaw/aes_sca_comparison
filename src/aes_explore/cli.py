"""
Command-line interface for AES Architecture Exploration.

Usage:
    python -m aes_explore.cli run --model unprotected_ht --key <hex32> --pt <hex32> --verbose
    python -m aes_explore.cli run --model dom --d 1 --key <hex32> --pt <hex32> --verbose --seed 123
    python -m aes_explore.cli round --model unprotected_ht --verbose
    python -m aes_explore.cli round --model dom --d 1 --verbose --seed 42
"""

import argparse
import sys
from typing import TextIO

from . import DEFAULT_KEY_HEX, DEFAULT_PT_HEX
from .reference import verify_ciphertext, get_expected_ciphertext
from .trace import TraceRecorder, print_result, print_header
from .utils import hex_to_bytes, bytes_to_hex
from .models.model_unprotected_ht import encrypt_unprotected_ht
from .models.model_dom import encrypt_dom
from .round_didactic import run_unprotected_round, run_dom_round


def run_command(args: argparse.Namespace) -> int:
    """Execute the 'run' command."""

    # Handle key
    if args.key:
        key_hex = args.key
        key_source = "provided"
    else:
        key_hex = DEFAULT_KEY_HEX
        key_source = "default (FIPS-197)"

    # Handle plaintext
    if args.pt:
        pt_hex = args.pt
        pt_source = "provided"
    else:
        pt_hex = DEFAULT_PT_HEX
        pt_source = "default (FIPS-197)"

    # Parse hex values
    try:
        key = hex_to_bytes(key_hex)
        if len(key) != 16:
            print(f"Error: Key must be 32 hex chars (16 bytes), got {len(key_hex)} chars")
            return 1
    except ValueError as e:
        print(f"Error: Invalid key hex: {e}")
        return 1

    try:
        plaintext = hex_to_bytes(pt_hex)
        if len(plaintext) != 16:
            print(f"Error: Plaintext must be 32 hex chars (16 bytes), got {len(pt_hex)} chars")
            return 1
    except ValueError as e:
        print(f"Error: Invalid plaintext hex: {e}")
        return 1

    # Print input info
    print_header(f"AES-128 Encryption: {args.model}")
    print(f"Key:       {key_hex} ({key_source})")
    print(f"Plaintext: {pt_hex} ({pt_source})")

    # Setup trace file if requested
    trace_file: TextIO | None = None
    if args.trace:
        try:
            trace_file = open(args.trace, 'w')
        except IOError as e:
            print(f"Error: Cannot open trace file: {e}")
            return 1

    # Create tracer
    tracer = TraceRecorder(verbose=args.verbose, trace_file=trace_file)

    try:
        # Run appropriate model
        if args.model == "unprotected_ht":
            ciphertext, cycles = encrypt_unprotected_ht(key, plaintext, tracer)
            random_bits = None

        elif args.model == "dom":
            # Get DOM-specific parameters
            d = args.d if args.d else 1
            sbox_variant = args.sbox_variant if args.sbox_variant else 5
            seed = args.seed

            print(f"Protection order: d={d} ({d+1} shares)")
            print(f"S-box variant: {sbox_variant}-stage pipeline")
            if seed is not None:
                print(f"RNG seed: {seed}")

            ciphertext, cycles, random_bits = encrypt_dom(
                key, plaintext,
                d=d,
                sbox_variant=sbox_variant,
                seed=seed,
                tracer=tracer,
            )

        else:
            print(f"Error: Unknown model '{args.model}'")
            print("Available models: unprotected_ht, dom")
            return 1

        # Verify against reference
        passed = verify_ciphertext(ciphertext, key, plaintext)

        # Get expected for comparison
        expected = get_expected_ciphertext(key, plaintext)

        # Print result
        ciphertext_hex = bytes_to_hex(ciphertext)
        print_result(ciphertext_hex, cycles, random_bits, passed)

        if not passed:
            print(f"Expected: {bytes_to_hex(expected)}")
            print(f"Got:      {ciphertext_hex}")
            return 1

        return 0

    finally:
        if trace_file:
            trace_file.close()


def round_command(args: argparse.Namespace) -> int:
    """Execute the 'round' command (didactic single-round walkthrough)."""

    # Handle key
    if args.key:
        key_hex = args.key
    else:
        key_hex = DEFAULT_KEY_HEX

    # Handle plaintext
    if args.pt:
        pt_hex = args.pt
    else:
        pt_hex = DEFAULT_PT_HEX

    # Parse hex values
    try:
        key = hex_to_bytes(key_hex)
        if len(key) != 16:
            print(f"Error: Key must be 32 hex chars (16 bytes), got {len(key_hex)} chars")
            return 1
    except ValueError as e:
        print(f"Error: Invalid key hex: {e}")
        return 1

    try:
        plaintext = hex_to_bytes(pt_hex)
        if len(plaintext) != 16:
            print(f"Error: Plaintext must be 32 hex chars (16 bytes), got {len(pt_hex)} chars")
            return 1
    except ValueError as e:
        print(f"Error: Invalid plaintext hex: {e}")
        return 1

    # Setup trace file if requested
    trace_file: TextIO | None = None
    if args.trace:
        try:
            trace_file = open(args.trace, 'w')
        except IOError as e:
            print(f"Error: Cannot open trace file: {e}")
            return 1

    try:
        if args.model == "unprotected_ht":
            result = run_unprotected_round(
                key, plaintext,
                verbose=args.verbose,
                trace_file=trace_file,
            )
            print(f"\nState entering Round 1: {_state_to_hex(result['state_in_round1'])}")
            print(f"State after   Round 1: {_state_to_hex(result['state_out_round1'])}")
            print(f"Cycles: {result['cycles']}")

        elif args.model == "dom":
            d = args.d if args.d else 1
            sbox_variant = args.sbox_variant if args.sbox_variant else 5
            seed = args.seed

            result = run_dom_round(
                key, plaintext,
                d=d,
                sbox_variant=sbox_variant,
                seed=seed,
                verbose=args.verbose,
                trace_file=trace_file,
            )
            print(f"\nState entering Round 1 (recombined): {_state_to_hex(result['state_in_round1'])}")
            print(f"State after   Round 1 (recombined): {_state_to_hex(result['state_out_round1'])}")
            print(f"Cycles: {result['cycles']}")
            print(f"Random bits consumed: {result['random_bits']}")

        else:
            print(f"Error: Unknown model '{args.model}'")
            print("Available models: unprotected_ht, dom")
            return 1

        return 0

    finally:
        if trace_file:
            trace_file.close()


def _state_to_hex(state: list[list[int]]) -> str:
    """Format a 4x4 state as hex string (column-major)."""
    from .utils import state_to_hex
    return state_to_hex(state)


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    """Add options shared by 'run' and 'round' subcommands."""
    parser.add_argument(
        "--model",
        required=True,
        choices=["unprotected_ht", "dom"],
        help="Model to use: unprotected_ht or dom",
    )
    parser.add_argument(
        "--key",
        help="AES-128 key as 32 hex chars (default: FIPS-197 test key)",
    )
    parser.add_argument(
        "--pt",
        help="Plaintext as 32 hex chars (default: FIPS-197 test plaintext)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed per-cycle traces",
    )
    parser.add_argument(
        "--trace",
        metavar="FILE",
        help="Output JSON Lines trace to file",
    )
    # DOM-specific options
    parser.add_argument(
        "--d",
        type=int,
        choices=[1, 2],
        default=1,
        help="Protection order for DOM model (default: 1)",
    )
    parser.add_argument(
        "--sbox-variant",
        type=int,
        choices=[5, 8],
        default=5,
        help="S-box pipeline variant: 5 or 8 stages (default: 5)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="RNG seed for DOM model (default: random)",
    )


def main(argv: list[str] | None = None) -> int:
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        prog="aes_explore",
        description="AES Architecture Exploration Tool",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 'run' command
    run_parser = subparsers.add_parser("run", help="Run full AES-128 encryption")
    _add_common_options(run_parser)

    # 'round' command
    round_parser = subparsers.add_parser(
        "round", help="Didactic walkthrough of Round 0 + Round 1 only"
    )
    _add_common_options(round_parser)

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "run":
        return run_command(args)
    elif args.command == "round":
        return round_command(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
