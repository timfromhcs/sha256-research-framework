"""
Task-Aware Model Router for SHA-256 Research Platform v3.0
Routes research tasks to appropriate model class and strictly prevents
cryptographic verification from ever being routed to an AI model.
"""

from typing import Dict, Any, Optional
from .runtime import LocalModelRuntime, CryptographicTruthViolationError


class TaskRouter:
    """Routes research tasks to models or delegates to cryptographic verifier."""

    def __init__(self, runtime: LocalModelRuntime):
        self.runtime = runtime

    def route_task(self, task_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Routes task to appropriate model class.
        
        Strictly forbids routing 'cryptographic_verification' or any attempt
        to evaluate truth of collisions/preimages with an AI model.
        """
        # HARD BOUNDARY: Cryptographic verification must NEVER route to an LLM/VLM
        if task_type in {"verify", "cryptographic_verification", "validate_collision", "validate_preimage"}:
            raise CryptographicTruthViolationError(
                "Hard scientific integrity boundary violated: "
                "Cryptographic verification must NEVER be routed to an LLM/VLM. "
                "All verifications must be executed exclusively by the IndependentVerifier."
            )

        if task_type in {"simple_planning", "hypothesis_generation"}:
            model_id = "v3-research-llm-local"
            prompt = payload.get("prompt", "Propose a next cryptanalysis hypothesis.")
            completion = self.runtime.generate_completion(model_id, prompt)
            return {"routed_to": model_id, "output": completion, "task_type": task_type}

        elif task_type in {"research_reasoning", "experiment_design"}:
            model_id = "v3-research-llm-local"
            prompt = payload.get("prompt", "Design a reduced-round SAT experiment.")
            completion = self.runtime.generate_completion(model_id, prompt)
            return {"routed_to": model_id, "output": completion, "task_type": task_type}

        elif task_type in {"image_analysis", "plot_analysis", "visual_inspection"}:
            model_id = "v3-vlm-analyzer-local"
            # Delegate to VLM
            return {
                "routed_to": model_id,
                "task_type": task_type,
                "status": "ready_for_vlm",
                "model_id": model_id
            }

        elif task_type in {"semantic_retrieval", "embed"}:
            model_id = "v3-embedding-retriever-local"
            text = payload.get("text", "")
            embedding = self.runtime.generate_embedding(model_id, text)
            return {"routed_to": model_id, "embedding": embedding, "task_type": task_type}

        else:
            raise ValueError(f"Unknown task_type: {task_type}")
