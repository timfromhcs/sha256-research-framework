"""
Model Manifest Specification for SHA-256 Research Platform v3.0
Defines model metadata, format, capabilities, and validation.
"""

import json
import os
import hashlib
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any


@dataclass
class ModelManifest:
    model_id: str
    name: str
    model_class: str  # "ResearchLLM", "VisionLanguageModel", "EmbeddingModel"
    format: str       # "GGUF", "ONNX", "Mock"
    quantization: str # "Q4_K_M", "Q8_0", "FP16", "N/A"
    context_length: int
    runtime: str      # "llama.cpp", "onnxruntime", "mock"
    backend: str      # "vulkan", "cpu"
    size_bytes: int
    checksum: str     # SHA-256 of weight file
    capabilities: List[str]
    file_path: Optional[str] = None
    description: Optional[str] = None

    def validate(self) -> bool:
        if self.model_class not in {"ResearchLLM", "VisionLanguageModel", "EmbeddingModel"}:
            raise ValueError(f"Invalid model_class: {self.model_class}")
        if self.format not in {"GGUF", "ONNX", "Mock"}:
            raise ValueError(f"Invalid format: {self.format}")
        if self.backend not in {"vulkan", "cpu"}:
            raise ValueError(f"Invalid backend: {self.backend}")
        if self.context_length < 1:
            raise ValueError("context_length must be >= 1")
        return True

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["capabilities_json"] = json.dumps(self.capabilities)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModelManifest":
        caps = data.get("capabilities", [])
        if isinstance(caps, str):
            try:
                caps = json.loads(caps)
            except Exception:
                caps = [caps]
        return cls(
            model_id=data["model_id"],
            name=data["name"],
            model_class=data["model_class"],
            format=data.get("format", "GGUF"),
            quantization=data.get("quantization", "N/A"),
            context_length=int(data.get("context_length", 2048)),
            runtime=data.get("runtime", "llama.cpp"),
            backend=data.get("backend", "cpu"),
            size_bytes=int(data.get("size_bytes", 0)),
            checksum=data.get("checksum", ""),
            capabilities=caps,
            file_path=data.get("file_path"),
            description=data.get("description")
        )

    @classmethod
    def from_json_file(cls, path: str) -> "ModelManifest":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        manifest = cls.from_dict(data)
        manifest.validate()
        return manifest
