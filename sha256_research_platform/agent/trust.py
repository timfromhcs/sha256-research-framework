"""
Epistemic Trust Levels for SHA-256 Research Platform v3.1
Defines hierarchical truth levels:
  L0: Model Suggestion
  L1: Unverified Observation
  L2: Experiment Output
  L3: Independently Verified
  L4: Reproduced
  L5: Cross-Environment Reproduced

Enforces that unverified findings can NEVER be promoted to L3 without an
authentic verdict from the segregated IndependentVerifier. A promotion
payload must therefore carry both a positive `is_valid` and explicit
verifier provenance; a bare boolean is not sufficient evidence.
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


# Verdicts must name the segregated engine that produced them.
VERIFIER_PROVENANCE_KEYS = ("verified_by", "verifier_engine")


class EpistemicTrustManager:
    """Manages assignment and promotion of epistemic trust levels."""

    @staticmethod
    def validate_promotion(
        current_level: str,
        target_level: str,
        verifier_verdict: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Validate that promotion to L3+ strictly possesses authentic proof.

        A payload is only accepted when it (a) reports is_valid True, (b) names
        the segregated IndependentVerifier as its source, and (c) carries a
        classification consistent with the round count it claims.
        """
        if target_level not in {"L3", "L4", "L5"}:
            return True

        if not verifier_verdict:
            raise EpistemicIntegrityError(
                f"Promotion to {target_level} rejected: Requires verifier verdict "
                f"from IndependentVerifier."
            )

        if not verifier_verdict.get("is_valid", False):
            raise EpistemicIntegrityError(
                f"Promotion to {target_level} rejected: Verifier verdict is_valid is False."
            )

        provenance = None
        for key in VERIFIER_PROVENANCE_KEYS:
            if verifier_verdict.get(key):
                provenance = verifier_verdict[key]
                break
        if provenance != "IndependentVerifier":
            raise EpistemicIntegrityError(
                f"Promotion to {target_level} rejected: verdict lacks IndependentVerifier "
                f"provenance (found {provenance!r})."
            )

        classification = verifier_verdict.get("classification")
        if classification == "StandardFullCollision":
            actual_rounds = verifier_verdict.get("actual_rounds", 0)
            if actual_rounds != 64:
                raise EpistemicIntegrityError(
                    f"Promotion rejected: Claimed StandardFullCollision on {actual_rounds} "
                    f"rounds (must be 64)."
                )
        if classification == "StandardFullPreimage":
            actual_rounds = verifier_verdict.get("actual_rounds", 0)
            if actual_rounds != 64:
                raise EpistemicIntegrityError(
                    f"Promotion rejected: Claimed StandardFullPreimage on {actual_rounds} "
                    f"rounds (must be 64)."
                )

        return True
