"""
Trace recording and pretty printing for AES operations.

Contains:
- VerboseTracer: structured, readable verbose output for DOM AES
- TraceRecorder: JSON Lines trace + simple verbose for unprotected model
- print_header / print_result: shared formatting helpers
"""

import json
from typing import Any, TextIO

from .utils import format_state_grid, format_state_line, state_to_hex
from .counters import RandomnessCounter


# ------------------------------------------------------------------
# Formatting helpers
# ------------------------------------------------------------------

def _fmt_draw_range(first_id: int, last_id_exclusive: int) -> str:
    """Format draw-ID range as a compact string."""
    if first_id >= last_id_exclusive:
        return "[]"
    if last_id_exclusive - first_id == 1:
        return f"[r{first_id:06d}]"
    return f"[r{first_id:06d}..r{last_id_exclusive - 1:06d}]"


def _fmt_state_words(state: list[list[int]]) -> str:
    """Format state as 4 space-separated 32-bit words (column-major)."""
    words = []
    for col in range(4):
        w = ""
        for row in range(4):
            w += f"{state[row][col]:02x}"
        words.append(w)
    return " ".join(words)


def _fmt_state_flat(state: list[list[int]]) -> str:
    """Format state as 32-char hex (column-major, no spaces)."""
    return state_to_hex(state)


def _compute_delta(
    old_state: list[list[int]] | None,
    new_state: list[list[int]],
    max_show: int = 8,
) -> str:
    """Compute byte-wise delta between two recombined states."""
    if old_state is None:
        return "(initial)"

    changes: list[str] = []
    for col in range(4):
        for row in range(4):
            idx = col * 4 + row
            ov = old_state[row][col]
            nv = new_state[row][col]
            if ov != nv:
                changes.append(f"b[{idx:d}]={ov:02x}\u2192{nv:02x}")

    if not changes:
        return "(no change)"
    if len(changes) <= max_show:
        return " ".join(changes)
    return " ".join(changes[:max_show]) + f" +{len(changes) - max_show} more"


def _fmt_pipe_occupancy(occupancy: list[int | None], num_stages: int) -> str:
    """Format pipeline occupancy as fixed-width string."""
    parts = []
    for i in range(num_stages):
        if i < len(occupancy) and occupancy[i] is not None:
            parts.append(f"S{i}=b{occupancy[i]:02d}")
        else:
            parts.append(f"S{i}=---")
    return " ".join(parts)


# ------------------------------------------------------------------
# VerboseTracer  –  structured DOM verbose output
# ------------------------------------------------------------------

class VerboseTracer:
    """
    Produces the structured cycle-by-cycle verbose trace for DOM AES.

    Created and attached to a TraceRecorder by the DomModel when
    --verbose is active.  The unprotected model ignores this entirely.
    """

    def __init__(self, rng_counter: RandomnessCounter):
        self.rc = rng_counter
        self._prev_recombined: list[list[int]] | None = None

    # ---- header / footer ----

    def header(self, d: int, seed: int | None, sbox_variant: int,
               pt_hex: str, key_hex: str) -> None:
        seed_desc = str(seed) if seed is not None else "random"
        print()
        print(f"DOM AES-128 run  d={d} ({d+1} shares)  "
              f"seed={seed_desc}  sbox_variant={sbox_variant}")
        print(f"PT: {pt_hex}")
        print(f"K : {key_hex}")
        stream = "deterministic" if seed is not None else "random"
        print(f"RNG: {stream} stream, accounting enabled")
        print()

    # ---- init events (key_mask, state_mask_init) ----

    def init_event(self, name: str,
                   shares: list[list[list[int]]],
                   recombined: list[list[int]]) -> None:
        inc = self.rc.bits_since_snapshot()
        first, last = self.rc.ids_since_snapshot()
        total = self.rc.total_bits

        print(f"C0000 INIT {name}")
        print(f"  RND:+{inc}b (tot={total}b) "
              f"draws={_fmt_draw_range(first, last)} purpose={name}")

        if "key" in name:
            pfx, label = "K", "KEY shares:"
        else:
            pfx, label = "S", "STATE shares:"

        print(f"  {label}")
        for i, sh in enumerate(shares):
            print(f"    {pfx}_S{i}: {_fmt_state_flat(sh)}")
        print(f"    XOR : {_fmt_state_flat(recombined)}")

        self._prev_recombined = _copy(recombined)

    # ---- per-cycle dashboard ----

    def cycle_line(
        self,
        cycle: int,
        round_num: int,
        op: str,
        recombined: list[list[int]] | None = None,
        pipe_occ: list[int | None] | None = None,
        num_stages: int = 0,
        pop_info: list[dict] | None = None,
    ) -> None:
        inc = self.rc.bits_since_snapshot()
        first, last = self.rc.ids_since_snapshot()
        total = self.rc.total_bits
        purposes: set[str] = set()
        for d in self.rc.draws_since_snapshot():
            if d["operation"]:
                purposes.add(d["operation"])

        # main line
        cs = f"C{cycle:04d}"
        rs = f"R{round_num}"
        os_ = f"{op:20s}"

        if recombined is not None:
            delta = _compute_delta(self._prev_recombined, recombined)
            print(f"{cs} {rs}  {os_} STATE:{_fmt_state_words(recombined)}  "
                  f"\u0394:{delta}")
            self._prev_recombined = _copy(recombined)
        else:
            print(f"{cs} {rs}  {os_}")

        # RNG line
        draws_str = _fmt_draw_range(first, last)
        pur = ""
        if purposes and inc > 0:
            pur = f" purposes=[{','.join(sorted(purposes))}]"
        print(f"  RND:+{inc}b (tot={total}b) draws={draws_str}{pur}")

        # pipeline occupancy
        if pipe_occ is not None:
            print(f"  PIPE: {_fmt_pipe_occupancy(pipe_occ, num_stages)}")

        # pop summary
        if pop_info:
            parts = []
            for p in pop_info[:4]:
                parts.append(f"b{p['byte_index']:02d} out={p['recombined']:02x}")
            line = "  ".join(parts)
            extra = len(pop_info) - 4
            if extra > 0:
                line += f"  +{extra} more"
            print(f"  POP: {line}")

    # ---- operation boundaries ----

    def op_boundary(self, round_num: int, op: str, direction: str,
                    recombined: list[list[int]]) -> None:
        print(f"-- R{round_num} {op} {direction} --")
        tag = "IN " if direction == "begin" else "OUT"
        print(f"  {tag}: {_fmt_state_words(recombined)}")

    # ---- share dump (at boundaries only) ----

    def share_dump(self, shares: list[list[list[int]]],
                   recombined: list[list[int]],
                   label: str = "") -> None:
        if label:
            print(f"  {label}:")
        for i, sh in enumerate(shares):
            print(f"    S{i}: {_fmt_state_flat(sh)}")
        print(f"    XOR: {_fmt_state_flat(recombined)}")


def _copy(state: list[list[int]]) -> list[list[int]]:
    return [row[:] for row in state]


# ------------------------------------------------------------------
# TraceRecorder  –  keeps JSON + simple unprotected verbose
# ------------------------------------------------------------------

class TraceRecorder:
    """
    Records and outputs traces of AES execution.

    Supports:
    - JSON Lines file output  (always, when trace_file is set)
    - Simple verbose stdout   (unprotected model – no VerboseTracer)
    - Structured verbose       (DOM model – via attached VerboseTracer)
    """

    def __init__(self, verbose: bool = False, trace_file: TextIO | None = None):
        self.verbose = verbose
        self.trace_file = trace_file
        self._records: list[dict[str, Any]] = []
        # Attached by DomModel when verbose is active
        self.vtracer: VerboseTracer | None = None

    def record(self, **kwargs) -> None:
        """
        Record a trace entry.

        For the unprotected model this also drives verbose stdout output.
        For the DOM model, verbose output is driven by VerboseTracer methods
        called directly from the model; record() only stores the JSON entry.
        """
        self._records.append(kwargs)

        if self.trace_file:
            self._write_jsonl(kwargs)

        # Simple verbose fallback (unprotected model only)
        if self.verbose and self.vtracer is None:
            self._print_verbose_simple(kwargs)

    def _write_jsonl(self, record: dict[str, Any]) -> None:
        serializable = self._make_serializable(record)
        self.trace_file.write(json.dumps(serializable) + "\n")
        self.trace_file.flush()

    def _make_serializable(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: self._make_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_serializable(item) for item in obj]
        elif isinstance(obj, bytes):
            return obj.hex()
        else:
            return obj

    def _print_verbose_simple(self, record: dict[str, Any]) -> None:
        """Compact verbose line for the unprotected model."""
        cycle = record.get("cycle", "?")
        round_num = record.get("round", "?")
        operation = record.get("operation", "unknown")

        if "state" in record:
            state_hex = format_state_line(record["state"])
            print(f"C{cycle:04d} R{round_num}  {operation:30s} STATE:{state_hex}")

    def get_records(self) -> list[dict[str, Any]]:
        return list(self._records)

    def clear(self) -> None:
        self._records.clear()


# ------------------------------------------------------------------
# Shared formatting functions
# ------------------------------------------------------------------

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
