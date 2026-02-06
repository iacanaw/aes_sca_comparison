"""
Trace recording and pretty printing for AES operations.
"""

import json
from typing import Any, TextIO

from .utils import format_state_grid, format_state_line


class TraceRecorder:
    """
    Records and outputs traces of AES execution.

    Supports both human-readable verbose output and JSON Lines format.
    """

    def __init__(self, verbose: bool = False, trace_file: TextIO | None = None):
        """
        Initialize trace recorder.

        Args:
            verbose: If True, print human-readable traces to stdout
            trace_file: If provided, write JSON Lines to this file
        """
        self.verbose = verbose
        self.trace_file = trace_file
        self._records: list[dict[str, Any]] = []

    def record(self, **kwargs) -> None:
        """
        Record a trace entry.

        Common fields:
            cycle: int - Current cycle number
            round: int - Current AES round (0-10)
            operation: str - Name of operation
            state: list[list[int]] - Current state (4x4)
            shares: list[list[list[int]]] - State shares for DOM model
            round_key: list[list[int]] - Round key being applied
        """
        self._records.append(kwargs)

        if self.trace_file:
            self._write_jsonl(kwargs)

        if self.verbose:
            self._print_verbose(kwargs)

    def _write_jsonl(self, record: dict[str, Any]) -> None:
        """Write a single record as JSON line."""
        # Convert nested lists to serializable format
        serializable = self._make_serializable(record)
        self.trace_file.write(json.dumps(serializable) + "\n")
        self.trace_file.flush()

    def _make_serializable(self, obj: Any) -> Any:
        """Convert object to JSON-serializable format."""
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, bytes):
            return obj.hex()
        else:
            return obj

    def _print_verbose(self, record: dict[str, Any]) -> None:
        """Print human-readable trace entry."""
        cycle = record.get("cycle", "?")
        round_num = record.get("round", "?")
        operation = record.get("operation", "unknown")

        print(f"\n{'='*60}")
        print(f"Cycle: {cycle}  |  Round: {round_num}  |  Operation: {operation}")
        print(f"{'='*60}")

        # Print state if present
        if "state" in record:
            print("\nState:")
            print(format_state_grid(record["state"]))
            print(f"  (hex: {format_state_line(record['state'])})")

        # Print shares if present (DOM model)
        if "shares" in record:
            shares = record["shares"]
            print(f"\nState Shares ({len(shares)} shares):")
            for i, share in enumerate(shares):
                print(f"\n  Share {i}:")
                print(format_state_grid(share))
                print(f"    (hex: {format_state_line(share)})")

            # Print recombined state
            if "recombined" in record:
                print("\n  Recombined (XOR of shares):")
                print(format_state_grid(record["recombined"]))
                print(f"    (hex: {format_state_line(record['recombined'])})")

        # Print round key if present
        if "round_key" in record:
            print("\nRound Key:")
            print(format_state_grid(record["round_key"]))

        # Print S-box details if present
        if "sbox_stage" in record:
            print(f"\n  S-box Stage: {record['sbox_stage']}")

        if "sbox_byte_index" in record:
            print(f"  Byte Index: {record['sbox_byte_index']}")

        if "sbox_input_shares" in record:
            shares = record["sbox_input_shares"]
            print(f"  Input Shares: {[f'0x{s:02x}' for s in shares]}")

        if "sbox_output_shares" in record:
            shares = record["sbox_output_shares"]
            print(f"  Output Shares: {[f'0x{s:02x}' for s in shares]}")

        if "sbox_recombined_input" in record:
            print(f"  Recombined Input: 0x{record['sbox_recombined_input']:02x}")

        if "sbox_recombined_output" in record:
            print(f"  Recombined Output: 0x{record['sbox_recombined_output']:02x}")

        # Print intermediate values if present
        if "intermediates" in record:
            print("\n  Intermediate Values:")
            for name, value in record["intermediates"].items():
                if isinstance(value, list):
                    formatted = [f"0x{v:02x}" if isinstance(v, int) and v < 256
                                else f"0x{v:x}" for v in value]
                    print(f"    {name}: {formatted}")
                elif isinstance(value, int):
                    print(f"    {name}: 0x{value:02x}")
                else:
                    print(f"    {name}: {value}")

        # Print counters if present
        if "cycles_so_far" in record:
            print(f"\n  Cycles so far: {record['cycles_so_far']}")

        if "random_bits_so_far" in record:
            print(f"  Random bits so far: {record['random_bits_so_far']}")

    def get_records(self) -> list[dict[str, Any]]:
        """Get all recorded entries."""
        return list(self._records)

    def clear(self) -> None:
        """Clear all records."""
        self._records.clear()


def print_header(title: str) -> None:
    """Print a section header."""
    print(f"\n{'#'*70}")
    print(f"# {title}")
    print(f"{'#'*70}")


def print_subheader(title: str) -> None:
    """Print a subsection header."""
    print(f"\n{'-'*50}")
    print(f"  {title}")
    print(f"{'-'*50}")


def print_result(ciphertext_hex: str, cycles: int,
                random_bits: int | None = None,
                passed: bool = True) -> None:
    """Print final encryption result."""
    print(f"\n{'='*70}")
    print("RESULT")
    print(f"{'='*70}")
    print(f"Ciphertext: {ciphertext_hex}")
    print(f"Cycles: {cycles}")

    if random_bits is not None:
        print(f"Random bits consumed: {random_bits}")

    status = "PASS" if passed else "FAIL"
    marker = "[OK]" if passed else "[ERROR]"
    print(f"Verification: {marker} {status}")
    print(f"{'='*70}")
