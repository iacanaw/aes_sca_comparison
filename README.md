# AES Architecture Exploration

A Python project for exploring AES-128 encryption architectures with two functional models:

1. **Unprotected High-Throughput Model** - One AES round per cycle with 16 parallel LUT S-boxes
2. **Domain-Oriented Masking (DOM) Model** - Masked AES with Canright-style S-box pipeline

## Features

- Explicit, simple, modifiable code (no numpy, no metaprogramming)
- Detailed verbose tracing of all AES stages
- Cycle and randomness bit counting
- JSON Lines trace output for machine-diffable analysis
- Verification against PyCryptodome reference implementation

## Requirements

- Python 3.11+
- PyCryptodome (for reference verification)
- pytest (for testing)

## Setup

### Linux/macOS

```bash
# Create virtual environment
python3 -m venv .venv

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Windows PowerShell

```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Commands

```bash
# Activate venv first (see Setup above)

# Run unprotected high-throughput model
python -m aes_explore.cli run --model unprotected_ht --key 2b7e151628aed2a6abf7158809cf4f3c --pt 3243f6a8885a308d313198a2e0370734

# Run DOM model with d=1 (2 shares), 5-stage S-box
python -m aes_explore.cli run --model dom --d 1 --key 2b7e151628aed2a6abf7158809cf4f3c --pt 3243f6a8885a308d313198a2e0370734 --seed 123 --sbox-variant 5

# Run DOM model with d=2 (3 shares), 8-stage S-box
python -m aes_explore.cli run --model dom --d 2 --key 2b7e151628aed2a6abf7158809cf4f3c --pt 3243f6a8885a308d313198a2e0370734 --seed 456 --sbox-variant 8
```

### Verbose Mode

Add `--verbose` to see detailed per-cycle state traces:

```bash
python -m aes_explore.cli run --model unprotected_ht --verbose

python -m aes_explore.cli run --model dom --d 1 --sbox-variant 5 --verbose --seed 123
```

### Round Mode (Didactic Walkthrough)

The `round` subcommand performs **only** Round 0 (initial AddRoundKey) + Round 1 and explains every transformation step in detail. It accepts the same flags as `run`:

```bash
# Unprotected walkthrough (verbose)
python -m aes_explore.cli round --model unprotected_ht --verbose

# DOM walkthrough (d=1, 5-stage S-box)
python -m aes_explore.cli round --model dom --d 1 --sbox-variant 5 --seed 42 --verbose

# DOM with d=2 and JSONL trace
python -m aes_explore.cli round --model dom --d 2 --seed 99 --trace round_trace.jsonl --verbose
```

Output sections (when `--verbose` is active):
1. **State layout primer** — column-major indexing overview
2. **Inputs** — key, plaintext, round keys 0 and 1
3. **Pre-round (Round 0 AddRoundKey)** — per-byte XOR table
4. **Round 1 walkthrough** — SubBytes, ShiftRows, MixColumns, AddRoundKey with per-byte details
5. **Summary** — hex states entering/leaving Round 1

For DOM mode, each stage also shows per-share matrices and recombined values.

### JSON Trace Output

Add `--trace <filename>` to output machine-readable JSON Lines:

```bash
python -m aes_explore.cli run --model dom --d 1 --trace trace.jsonl --seed 123
```

### Default Values

If `--key` and/or `--pt` are not provided, the following defaults are used:

- **Default Key**: `2b7e151628aed2a6abf7158809cf4f3c` (FIPS-197 Appendix B)
- **Default Plaintext**: `3243f6a8885a308d313198a2e0370734` (FIPS-197 Appendix B)
- **Expected Ciphertext**: `3925841d02dc09fbdc118597196a0b32`

## CLI Options

```
python -m aes_explore.cli run   [OPTIONS]   # Full 10-round encryption
python -m aes_explore.cli round [OPTIONS]   # Didactic Round 0+1 walkthrough

Options (shared by both commands):
  --model TEXT        Model name: unprotected_ht or dom (required)
  --key TEXT          AES-128 key as 32 hex chars (optional, uses default)
  --pt TEXT           Plaintext as 32 hex chars (optional, uses default)
  --d INTEGER         Protection order for DOM model: 1 or 2 (default: 1)
  --sbox-variant INT  S-box pipeline variant: 5 or 8 (default: 5)
  --seed INTEGER      RNG seed for DOM model (default: random)
  --verbose           Print detailed per-cycle traces
  --trace TEXT        Output JSON Lines trace to file
```

## Output Format

Non-verbose output includes:
- Ciphertext (hex)
- Total cycles
- (DOM only) Fresh randomness bits consumed
- PASS/FAIL verification against PyCryptodome reference

## Running Tests

```bash
# Activate venv first
source .venv/bin/activate  # Linux/macOS
# or
.\.venv\Scripts\Activate.ps1  # Windows PowerShell

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_vectors.py -v
pytest tests/test_randomized_vs_library.py -v
```

## Project Structure

```
aes_exploration/
├── README.md                              # This file
├── requirements.txt                       # Dependencies
├── src/
│   └── aes_explore/
│       ├── __init__.py
│       ├── cli.py                         # Command-line interface
│       ├── reference.py                   # PyCryptodome wrapper
│       ├── utils.py                       # Byte/state conversions
│       ├── trace.py                       # TraceRecorder + pretty printers
│       ├── counters.py                    # CycleCounter, RandomnessCounter
│       ├── aes_core.py                    # Shared AES primitives
│       ├── round_didactic.py              # Didactic Round 0+1 walkthrough
│       ├── dom/
│       │   ├── __init__.py
│       │   ├── gf_canright.py             # GF(2^n) arithmetic helpers
│       │   ├── dom_gadgets.py             # DOM-indep and DOM-dep gadgets
│       │   └── sbox_canright_dom.py       # DOM Canright S-box pipeline
│       └── models/
│           ├── __init__.py
│           ├── model_unprotected_ht.py    # Unprotected high-throughput
│           └── model_dom.py               # Domain-oriented masking
└── tests/
    ├── __init__.py
    ├── test_vectors.py                    # Known AES-128 test vectors
    ├── test_randomized_vs_library.py      # Randomized verification tests
    └── test_round_mode.py                 # Round mode correctness tests
```

## Models Overview

### Model 1: Unprotected High-Throughput

- One AES round per cycle (cycles 1-9: full rounds, cycle 10: final round)
- 16 parallel LUT-based S-boxes
- Round keys pre-computed
- Cycle 0: Initial AddRoundKey

### Model 2: Domain-Oriented Masking (DOM)

- d+1 shares for protection order d (d=1: 2 shares, d=2: 3 shares)
- Byte-serial datapath (16 bytes processed sequentially through S-box)
- Canright-style S-box with subfield decomposition
- Two S-box variants:
  - **5-stage**: Uses DOM-dep multipliers in stages 1-3, DOM-indep in stage 4
  - **8-stage**: Uses DOM-indep everywhere with extra register stages

## License

Educational/Research use.
