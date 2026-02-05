"""AES implementation techniques for evaluation."""

from .unmasked_baseline import UnmaskedBaseline
from .masked_dom_skeleton import MaskedDOMSkeleton
from .masked_ti_skeleton import MaskedTISkeleton

# Registry of available techniques
TECHNIQUES: dict[str, type] = {
    "unmasked_baseline": UnmaskedBaseline,
    "masked_dom_skeleton": MaskedDOMSkeleton,
    "masked_ti_skeleton": MaskedTISkeleton,
}


def get_technique(name: str) -> type:
    """Get technique class by name.

    Args:
        name: Technique name

    Returns:
        Technique class

    Raises:
        KeyError: If technique not found
    """
    if name not in TECHNIQUES:
        available = ", ".join(TECHNIQUES.keys())
        raise KeyError(f"Unknown technique '{name}'. Available: {available}")
    return TECHNIQUES[name]


def list_techniques() -> list[dict[str, str]]:
    """List all available techniques with descriptions.

    Returns:
        List of dicts with 'name' and 'description' keys
    """
    result = []
    for name, cls in TECHNIQUES.items():
        result.append({
            "name": name,
            "description": getattr(cls, "description", "No description"),
        })
    return result


__all__ = [
    "TECHNIQUES",
    "get_technique",
    "list_techniques",
    "UnmaskedBaseline",
    "MaskedDOMSkeleton",
    "MaskedTISkeleton",
]
