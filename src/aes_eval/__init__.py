"""AES Side-Channel Resistant Implementation Evaluation Framework."""

__version__ = "0.1.0"

from .interfaces import EvalConfig, Result, BaseTechnique
from .golden import golden_encrypt
from .cycle_models import CycleModel, IterativeRoundsCycleModel
from .randomness import RandomSource

__all__ = [
    "EvalConfig",
    "Result",
    "BaseTechnique",
    "golden_encrypt",
    "CycleModel",
    "IterativeRoundsCycleModel",
    "RandomSource",
]
