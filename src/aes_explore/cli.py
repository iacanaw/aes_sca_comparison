"""
Command-line interface for AES Architecture Exploration.

Usage:
    python -m aes_explore.cli run --model unprotected_ht --key <hex32> --pt <hex32> --verbose
    python -m aes_explore.cli run --model dom --d 1 --key <hex32> --pt <hex32> --verbose --seed 123
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


def main(argv: list[str] | None = None) -> int:
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        prog="aes_explore",
        description="AES Architecture Exploration Tool",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 'run' command
    run_parser = subparsers.add_parser("run", help="Run AES encryption")
    run_parser.add_argument(
        "--model",
        required=True,
        choices=["unprotected_ht", "dom"],
        help="Model to use: unprotected_ht or dom",
    )
    run_parser.add_argument(
        "--key",
        help="AES-128 key as 32 hex chars (default: FIPS-197 test key)",
    )
    run_parser.add_argument(
        "--pt",
        help="Plaintext as 32 hex chars (default: FIPS-197 test plaintext)",
    )
    run_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed per-cycle traces",
    )
    run_parser.add_argument(
        "--trace",
        metavar="FILE",
        help="Output JSON Lines trace to file",
    )

    # DOM-specific options
    run_parser.add_argument(
        "--d",
        type=int,
        choices=[1, 2],
        default=1,
        help="Protection order for DOM model (default: 1)",
    )
    run_parser.add_argument(
        "--sbox-variant",
        type=int,
        choices=[5, 8],
        default=5,
        help="S-box pipeline variant: 5 or 8 stages (default: 5)",
    )
    run_parser.add_argument(
        "--seed",
        type=int,
        help="RNG seed for DOM model (default: random)",
    )

    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "run":
        return run_command(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
