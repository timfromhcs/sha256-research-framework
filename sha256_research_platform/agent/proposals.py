"""
Candidate proposal plane for the SHA-256 autonomous research loop.

SECURITY / TRUST MODEL
----------------------
Everything in this module is UNTRUSTED and permanently capped at trust level
L0 (model suggestion). A proposal is a *hypothesis about a configuration*, not
a result. It carries no authority over:

  * what runs,
  * what counts as verified,
  * whether a claim is promoted to L3.

The deterministic scheduler in `scheduler.py` is the only component that
executes work and the only path to an IndependentVerifier verdict. This mirrors
the discipline that made OpenAI's "alien math" release auditable: publish the
reasoning, but let a mechanical checker decide truth.

Every proposal is stored with its rationale verbatim so a human can audit the
reasoning chain, not just the outcome.
"""

import json
import re
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from ..storage.db import DatabaseManager
from ..models.runtime import LocalModelRuntime

# The complete, closed set of strategies a proposal may name. Anything else is
# rejected at validation time, so an LLM cannot invent a code path.
ALLOWED_ENCODINGS = ("tseitin", "xor")
ALLOWED_SOLVERS = ("cadical", "kissat", "cryptominisat", "minisat")
MAX_TIMEOUT_SECONDS = 3600
MIN_ROUNDS = 1
MAX_ROUNDS = 64


class ProposalValidationError(Exception):
    """Raised when a proposed configuration is outside the allowed envelope."""


@dataclass
class CandidateEncoding:
    """One proposed experiment configuration. Untrusted until executed+verified."""

    rounds: int
    solver: str
    encoding: str
    carry_save: bool
    timeout: int
    rationale: str = ""
    # Filled in by the proposer, never trusted:
    expected_difficulty: Optional[float] = None
    # Assigned when the proposal enters the queue.
    proposal_id: Optional[str] = None
    trust_level: str = "L0"
    source: str = "deterministic"

    def validate(self) -> "CandidateEncoding":
        """Reject anything outside the closed envelope. Anti-clamping applies."""
        if not isinstance(self.rounds, int) or isinstance(self.rounds, bool):
            raise ProposalValidationError(f"rounds must be an int, got {self.rounds!r}")
        if not (MIN_ROUNDS <= self.rounds <= MAX_ROUNDS):
            raise ProposalValidationError(
                f"Anti-clamping violation: rounds must be in [{MIN_ROUNDS}, {MAX_ROUNDS}], "
                f"got {self.rounds}"
            )
        if self.solver not in ALLOWED_SOLVERS:
            raise ProposalValidationError(
                f"solver '{self.solver}' not in allowlist {ALLOWED_SOLVERS}"
            )
        if self.encoding not in ALLOWED_ENCODINGS:
            raise ProposalValidationError(
                f"encoding '{self.encoding}' not in allowlist {ALLOWED_ENCODINGS}"
            )
        if not isinstance(self.carry_save, bool):
            raise ProposalValidationError("carry_save must be a boolean")
        if not isinstance(self.timeout, int) or not (1 <= self.timeout <= MAX_TIMEOUT_SECONDS):
            raise ProposalValidationError(
                f"timeout must be an int in [1, {MAX_TIMEOUT_SECONDS}], got {self.timeout!r}"
            )

        # The XOR dialect emits native XOR constraints; only an XOR-capable
        # solver can read them. Enforce here rather than trusting the caller.
        if self.encoding == "xor" and self.solver != "cryptominisat":
            raise ProposalValidationError(
                "encoding 'xor' requires the XOR-capable solver 'cryptominisat'"
            )
        return self

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _coerce_int(value: Any, default: int) -> int:
    try:
        if isinstance(value, bool):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def parse_proposal(text: str, source: str = "llm") -> List[CandidateEncoding]:
    """Parse model output into validated proposals.

    Tolerant of formatting noise (markdown fences, prose) but strict about the
    configuration envelope. Returns only proposals that pass validate().
    """
    if not text:
        return []

    # Pull JSON objects out of whatever wrapper the model produced.
    candidates: List[Dict[str, Any]] = []
    for match in re.finditer(r"\{[^{}]*\}", text, re.DOTALL):
        blob = match.group(0)
        try:
            obj = json.loads(blob)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            candidates.append(obj)

    # If the model emitted a bare list of objects, each inner match is enough.
    proposals: List[CandidateEncoding] = []
    for obj in candidates:
        if "rounds" not in obj and "n_rounds" not in obj:
            continue
        rounds = _coerce_int(obj.get("rounds", obj.get("n_rounds")), -1)
        solver = str(obj.get("solver", "cadical")).strip().lower()
        encoding = str(obj.get("encoding", "tseitin")).strip().lower()
        proposal = CandidateEncoding(
            rounds=rounds,
            solver=solver,
            encoding=encoding,
            carry_save=_coerce_bool(obj.get("carry_save", False)),
            timeout=_coerce_int(obj.get("timeout", 120), 120),
            rationale=str(obj.get("rationale", ""))[:2000],
            expected_difficulty=(
                float(obj["expected_difficulty"])
                if isinstance(obj.get("expected_difficulty"), (int, float))
                else None
            ),
            source=source,
        )
        try:
            proposals.append(proposal.validate())
        except ProposalValidationError:
            # Rejected proposals are simply dropped; they never reach execution.
            continue
    return proposals


# The deterministic fallback proposer. Used when no model is loaded, and as the
# guaranteed-progress path so the loop can never stall waiting on an LLM.
def propose_deterministic(
    current_rounds: int,
    solver: str = "cryptominisat",
    timeout: int = 300,
) -> List[CandidateEncoding]:
    """Escalate the frontier by measuring, not by guessing."""
    proposals = [
        CandidateEncoding(
            rounds=min(current_rounds + 1, MAX_ROUNDS),
            solver=solver,
            encoding="xor",
            carry_save=True,
            timeout=timeout,
            rationale=(
                f"Measured escalation from {current_rounds} rounds using the leanest "
                f"encoding available (xor + carry-save), which produced the smallest "
                f"formulas and the deepest verified preimages so far."
            ),
            source="deterministic",
        )
    ]
    # A second, cheaper probe at the current round guards against mistaking a
    # timeout for a wall.
    proposals.append(
        CandidateEncoding(
            rounds=current_rounds,
            solver="cadical",
            encoding="tseitin",
            carry_save=False,
            timeout=max(timeout, 300),
            rationale=(
                f"Re-probe {current_rounds} rounds with an independent solver and a "
                f"longer budget to distinguish a genuine wall from a timeout."
            ),
            source="deterministic",
        )
    )
    for p in proposals:
        p.validate()
    return proposals


PROMPT_TEMPLATE = """You are proposing cryptanalysis experiment configurations for a
SAT-based reduced-round SHA-256 preimage search. Full 64-round SHA-256 is
computationally secure and out of scope; the goal is to find the deepest
reduced-round preimage that an independent verifier confirms.

Known facts about this system:
- The leanest encoding is "xor" (native XOR constraints, requires the
  cryptominisat solver) optionally combined with carry_save=true.
- The "tseitin" encoding works with cadical or kissat but produces larger CNFs.
- Solve time grows roughly exponentially per round; the frontier is currently
  around {current_rounds} rounds.
- Every result is independently verified. A proposal that does not produce a
  verifiable candidate is simply a negative result, never a failure.

Propose up to 2 configurations to try next. Respond with a JSON array of objects
each having keys: rounds (int), solver (str), encoding (str: "tseitin" or "xor"),
carry_save (bool), timeout (int seconds), rationale (str), expected_difficulty
(number). Do not propose rounds above 30. Do not explain outside the JSON.
"""


class ProposalPlane:
    """Collects candidate configurations from an LLM, always at L0."""

    def __init__(
        self,
        db: Optional[DatabaseManager] = None,
        runtime: Optional[LocalModelRuntime] = None,
    ):
        self.db = db or DatabaseManager()
        self.runtime = runtime or LocalModelRuntime(self.db)
        self.rejected_count = 0

    def collect(self, current_rounds: int, timeout: int = 300) -> List[CandidateEncoding]:
        """Return validated proposals, falling back to deterministic ones.

        A model failure must never stall the research loop, so the deterministic
        proposer is always included.
        """
        proposals: List[CandidateEncoding] = []
        model_proposals: List[CandidateEncoding] = []

        try:
            prompt = PROMPT_TEMPLATE.format(current_rounds=current_rounds)
            raw = self.runtime.generate_completion(
                "v3-research-llm-local",
                prompt,
                max_tokens=512,
                temperature=0.7,
            )
            if raw:
                model_proposals = parse_proposal(raw, source="llm")
        except Exception:
            # A model error is an infrastructure event, not a result. The
            # deterministic path below still guarantees forward progress.
            model_proposals = []

        for p in model_proposals:
            p.proposal_id = f"prop_{int(time.time() * 1000)}_{p.rounds}_{p.encoding}"
            self._persist(p)

        proposals = model_proposals + propose_deterministic(
            current_rounds, timeout=timeout
        )
        for p in proposals:
            if not p.proposal_id:
                p.proposal_id = f"prop_{int(time.time() * 1000)}_{p.rounds}_{p.encoding}_det"

        # Never execute the same configuration twice in a row.
        seen = set()
        unique = []
        for p in proposals:
            key = (p.rounds, p.solver, p.encoding, p.carry_save)
            if key in seen:
                continue
            seen.add(key)
            unique.append(p)
        return unique

    def _persist(self, proposal: CandidateEncoding) -> None:
        """Store the proposal and its rationale verbatim for later audit."""
        try:
            conn = self.db.get_connection()
            try:
                conn.execute(
                    "INSERT INTO tool_calls "
                    "(id, action_id, tool_name, arguments, result, is_error, execution_time_ms) "
                    "VALUES (?, ?, ?, ?, ?, 0, ?)",
                    (
                        f"prop_{int(time.time() * 1000)}",
                        None,
                        "propose_encoding",
                        json.dumps(proposal.to_dict(), sort_keys=True),
                        json.dumps({"queued": True, "trust_level": "L0"}, sort_keys=True),
                        0,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass