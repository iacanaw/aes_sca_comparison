"""
AES Architecture Exploration

Two functional AES-128 encryption models for architecture exploration:
1. Unprotected High-Throughput (one round per cycle)
2. Domain-Oriented Masking with Canright S-box
"""

__version__ = "1.0.0"

# Default AES-128 test values from FIPS-197 Appendix B
DEFAULT_KEY_HEX = "2b7e151628aed2a6abf7158809cf4f3c"
DEFAULT_PT_HEX = "3243f6a8885a308d313198a2e0370734"
DEFAULT_CT_HEX = "3925841d02dc09fbdc118597196a0b32"
