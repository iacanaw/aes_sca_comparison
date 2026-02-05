# AES Side-Channel Resistant Implementation Evaluation Framework

A Python framework for evaluating architectural tradeoffs of side-channel-resistant AES implementations to inform high-throughput AES IP design decisions.

## Purpose

This project helps hardware architects decide which side-channel-resistant AES technique and micro-architecture to use for a high-throughput AES IP by:

1. **Comparing implementations** against a golden AES reference (PyCryptodome)
2. **Evaluating tradeoffs** as a function of:
   - Datapath parallelism (number of S-boxes in parallel: 1-16)
   - Masking order (d = 0, 1, or 2 → shares = d+1)
   - Technique (unmasked baseline, DOM-like skeleton, TI-like skeleton)
3. **Quantifying costs** in cycles, randomness consumption, and area proxies

## Scope

### In Scope
- ECB single-block (16-byte) AES-128 encryption
- Cycle accounting with configurable S-box parallelism
- Randomness accounting for masking schemes
- Area proxy metrics based on parallelism and shares
- Skeleton implementations for DOM and TI masking (cost modeling, not production masking)
- CSV/JSON/Markdown reporting

### Non-Goals (Out of Scope)
- Production-ready masked implementations (skeletons model costs only)
- AES decryption
- Multi-block modes (CBC, CTR, GCM, etc.)
- AES-192/AES-256 key sizes
- Actual side-channel leakage analysis or power traces
- RTL/HDL generation

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLI (cli.py)                            │
│   list | validate | sweep | compare                             │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Reporting (reporting.py)                     │
│   CSV, JSON, Markdown generation                                │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Metrics (metrics.py)                        │
│   Latency, Throughput, Area Proxy calculations                  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌──────────────────────┬──────────────────────────────────────────┐
│   CycleModel         │          RandomSource                    │
│   (cycle_models.py)  │          (randomness.py)                 │
│                      │                                          │
│  - S-box parallelism │  - Deterministic seeding                 │
│  - Stage costs       │  - Per-category tracking                 │
│  - Round accounting  │  - Masking order scaling                 │
└──────────────────────┴──────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Technique Implementations                       │
│   implementations/                                              │
│   ├── unmasked_baseline.py                                      │
│   ├── masked_dom_skeleton.py                                    │
│   └── masked_ti_skeleton.py                                     │
│                                                                 │
│   All inherit from BaseTechnique (interfaces.py)                │
│   All validated against Golden Reference (golden.py)            │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│              Golden Reference (golden.py)                       │
│              PyCryptodome Crypto.Cipher.AES                     │
└─────────────────────────────────────────────────────────────────┘
```

## Evaluation Plan

### Test Vectors
1. **FIPS-197 Known Answer Tests (KATs)**: Official test vectors from the AES standard
2. **Randomized Tests**: 200+ random plaintext/key pairs validated against golden

### Sweep Parameters
| Parameter | Values | Description |
|-----------|--------|-------------|
| `sbox_parallelism` | {1, 4, 5, 8, 16} | S-boxes evaluated in parallel |
| `mask_order_d` | {0, 1, 2} | Masking order (shares = d+1) |
| `technique` | unmasked, DOM, TI | Implementation technique |
| `round_arch` | iterative_rounds | Round architecture |

### Validation Strategy
- Every configuration must produce ciphertext matching the golden reference
- Cycle counts must scale correctly with S-box parallelism (inversely)
- Randomness must scale with masking order (increases with d)

## Computed Metrics

### Cycle Metrics
| Metric | Formula | Description |
|--------|---------|-------------|
| `cycle_count_total` | Sum of all stages × 10 rounds | Total cycles for encryption |
| `sub_bytes_cycles` | `ceil(16 / sbox_par) × cost_per_group` | S-box stage cycles |
| `shift_rows_cycles` | Constant (default: 1) | ShiftRows stage |
| `mix_columns_cycles` | Constant (default: 1) | MixColumns stage |
| `add_round_key_cycles` | Constant (default: 1) | AddRoundKey stage |
| `key_schedule_cycles` | 10 × key expansion cost | Key schedule total |

### Randomness Metrics
| Metric | Formula | Description |
|--------|---------|-------------|
| `random_bits_total` | Sum of all categories | Total random bits consumed |
| `fresh_masks_bits` | `state_bytes × 8 × shares` | Initial masking |
| `remasking_bits` | Technique-specific | Inter-round remasking |
| `gadget_randomness` | `gadgets × bits_per_gadget × shares` | Gadget fresh randomness |

### Performance Metrics
| Metric | Formula | Description |
|--------|---------|-------------|
| `latency_cycles` | `cycle_count_total` | Cycles to encrypt one block |
| `latency_seconds` | `latency_cycles / f_clk_hz` | Wall-clock latency |
| `throughput_blocks_sec` | `f_clk_hz / latency_cycles` | Non-pipelined throughput |
| `throughput_gbps` | `throughput_blocks_sec × 128 / 1e9` | Throughput in Gbps |

### Area Proxy Metrics
| Metric | Formula | Description |
|--------|---------|-------------|
| `sbox_area_proxy` | `sbox_parallelism × sbox_base_area` | S-box hardware estimate |
| `register_area_proxy` | `shares × state_bytes × 8` | State register estimate |
| `composite_area` | `α×sbox + β×registers + γ×extras` | Weighted composite |

## File Tree

```
aes_sca_comparison/
├── README.md                          # This file
├── LICENSE                            # MIT License
├── pyproject.toml                     # Package configuration
├── .gitignore                         # Git ignore rules
├── src/
│   └── aes_eval/
│       ├── __init__.py
│       ├── golden.py                  # PyCryptodome golden reference
│       ├── interfaces.py              # Result, EvalConfig, BaseTechnique
│       ├── cycle_models.py            # CycleModel abstraction
│       ├── randomness.py              # RandomSource abstraction
│       ├── metrics.py                 # Metric calculations
│       ├── reporting.py               # CSV/JSON/Markdown export
│       ├── cli.py                     # Click CLI application
│       └── implementations/
│           ├── __init__.py
│           ├── unmasked_baseline.py   # Unmasked AES implementation
│           ├── masked_dom_skeleton.py # DOM-style masking skeleton
│           └── masked_ti_skeleton.py  # TI-style masking skeleton
├── tests/
│   ├── __init__.py
│   ├── test_golden.py                 # FIPS-197 KATs
│   ├── test_implementations.py        # Implementation correctness
│   ├── test_cycle_scaling.py          # Cycle monotonicity tests
│   └── test_randomness_scaling.py     # Randomness scaling tests
└── reports/                           # Generated reports (gitignored)
    ├── summary.csv
    ├── summary.json
    └── report.md
```

## Installation

```bash
# Clone and install in development mode
cd aes_sca_comparison
pip install -e .

# Verify installation
aes-eval --help
```

## How to Run

### List Available Techniques
```bash
aes-eval list
```

### Validate a Single Configuration
```bash
# Validate unmasked baseline with byte-serial S-box
aes-eval validate --tech unmasked_baseline --sbox-par 1

# Validate DOM skeleton with full parallelism and d=1
aes-eval validate --tech masked_dom_skeleton --sbox-par 16 --d 1
```

### Run a Parameter Sweep
```bash
# Default sweep: all techniques, common parallelism values, all masking orders
aes-eval sweep --tech all --sbox-par 1,5,16 --d 0,1,2 --n 200 --f-clk 200e6 --out reports/

# Custom sweep with specific techniques
aes-eval sweep --tech unmasked_baseline,masked_dom_skeleton --sbox-par 1,4,8,16 --d 0,1 --n 100 --out reports/
```

### Compare Specific Configurations
```bash
# Compare DOM and TI skeletons at full parallelism with d=1
aes-eval compare --tech masked_dom_skeleton,masked_ti_skeleton --sbox-par 16 --d 1 --n 1000
```

## How to Add a New Technique

1. Create a new file in `src/aes_eval/implementations/`:

```python
# src/aes_eval/implementations/my_new_technique.py
from aes_eval.interfaces import BaseTechnique, Result, EvalConfig
from aes_eval.cycle_models import CycleModel
from aes_eval.randomness import RandomSource

class MyNewTechnique(BaseTechnique):
    """Description of your technique."""

    name = "my_new_technique"
    description = "Brief description for CLI listing"

    def encrypt_block(
        self,
        key: bytes,
        plaintext: bytes,
        rng: RandomSource,
        cycle_model: CycleModel,
        config: EvalConfig,
    ) -> Result:
        # Implementation here
        # Must return correct ciphertext matching golden reference
        ...
```

2. Register in `src/aes_eval/implementations/__init__.py`:

```python
from .my_new_technique import MyNewTechnique

TECHNIQUES = {
    # ... existing techniques ...
    "my_new_technique": MyNewTechnique,
}
```

3. Add tests in `tests/test_implementations.py`.

## How to Add a New Micro-Architecture Model

1. Extend `CycleModel` in `src/aes_eval/cycle_models.py`:

```python
class MyCustomCycleModel(CycleModel):
    """Custom cycle model with different stage costs."""

    def __init__(self, sbox_parallelism: int, **kwargs):
        super().__init__(sbox_parallelism)
        # Custom initialization
        self.sbox_cycles_per_group = kwargs.get("sbox_cost", 3)

    def sub_bytes_cycles(self, num_bytes: int = 16) -> int:
        groups = math.ceil(num_bytes / self.sbox_parallelism)
        return groups * self.sbox_cycles_per_group
```

2. Register in `EvalConfig.round_arch` options.

## Configuration Object (EvalConfig)

The `EvalConfig` dataclass is passed to all components:

```python
@dataclass
class EvalConfig:
    aes_mode: str = "ecb_single_block"      # Fixed for now
    mask_order_d: int = 0                    # 0=unmasked, 1=2-share, 2=3-share
    sbox_parallelism: int = 16               # 1..16
    round_arch: str = "iterative_rounds"     # Round architecture
    f_clk_hz: float = 200e6                  # Clock frequency

    @property
    def shares(self) -> int:
        return self.mask_order_d + 1 if self.mask_order_d > 0 else 1
```

## Important Notes

### Skeleton Implementations

The DOM and TI "skeletons" in this framework are **not production-ready masked implementations**. They:

- **Do** produce correct ciphertext (validated against golden reference)
- **Do** model cycle and randomness costs realistically
- **Do NOT** provide actual side-channel protection

This is intentional: we are evaluating **architectural tradeoffs**, not implementing secure cryptography. The skeletons internally use an unmasked AES core for correctness while simulating the costs of masking.

### Randomness Model

The randomness accounting is an **estimation model**:

- Fresh masks: `shares × state_size_bits`
- DOM gadgets: `(shares-1) × shares / 2 × bits_per_gadget` per S-box
- TI gadgets: `shares × bits_per_gadget` per S-box
- Remasking: Configurable per-round refresh cost

These estimates are based on published literature but may differ from specific implementations.

### Cycle Model Assumptions

Default cycle costs (configurable):

| Stage | Default Cost | Notes |
|-------|-------------|-------|
| S-box group | 1 cycle | Per `ceil(16/sbox_par)` groups |
| ShiftRows | 1 cycle | Routing only |
| MixColumns | 1 cycle | Parallel column ops |
| AddRoundKey | 1 cycle | XOR operation |
| Key schedule | 1 cycle/round | Simplified |

## Dependencies

- **PyCryptodome**: Golden AES reference
- **pytest**: Testing framework
- **click**: CLI framework
- **tabulate**: Table formatting (optional)

## License

MIT License - see [LICENSE](LICENSE) file.
