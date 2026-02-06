"""
AES encryption models for architecture exploration.

Contains:
- model_unprotected_ht: Unprotected high-throughput model (1 round/cycle)
- model_dom: Domain-Oriented Masking protected model
"""

from .model_unprotected_ht import UnprotectedHTModel
from .model_dom import DomModel

__all__ = ["UnprotectedHTModel", "DomModel"]
