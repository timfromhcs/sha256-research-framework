"""
Epistemic Trust Levels for SHA-256 Research Platform v3.0
Defines hierarchical truth levels:
  L0: Model Suggestion
  L1: Unverified Observation
  L2: Experiment Output
  L3: Independently Verified
  L4: Reproduced
  L5: Cross-Environment Reproduced
Enforces that unverified findings can NEVER be promoted to L3 without
an authentic verification verdict from the IndependentVerifier.
"""

from enum import Enum
from typing import Dict, Any, Optional


class TrustLevel(str, Enum):
    L0 = "L0"  # Model Suggestion
    L1 = "L1"  # Unverified Observation
    L2 = "L2"  # Experiment Output
    L3 = "L3"  # Independently Verified
    L4 = "L4"  # Reproduced
    L5 = "L5"  # Cross-Environment Reproduced


class EpistemicIntegrityError(Exception):
    """Raised when an invalid epistemic transition is attempted."""
    pass


class EpistemicTrustManager:
    """Manages assignment and promotion of epistemic trust levels."""

    @staticmethod
    def validate_promotion(current_level: str, target_level: str, verifier_verdict: Optional[Dict[str, Any]] = None) -> bool:
        """Validates that promotion to L3+ strictly possesses authentic IndependentVerifier proof."""
        if target_level in {"L3", "L4", "L5"}:
            if not verifier_verdict:
                raise EpistemicIntegrityError(
                    f"Promotion to {target_level} rejected: Requires verifier verdict from IndependentVerifier."
                )
            if not verifier_verdict.get("is_valid", False):
                raise EpistemicIntegrityError(
                    f"Promotion to {target_level} rejected: Verifier verdict is_valid is False."
                )
            if verifier_verdict.get("classification") == "StandardFullCollision":
                actual_rounds = verifier_verdict.get("actual_rounds", 0)
                if actual_rounds != 64:
                    raise EpistemicIntegrityError(
                        f"Promotion rejected: Claimed StandardFullCollision on {actual_rounds} rounds (must be 64)."
                    )
        return True
