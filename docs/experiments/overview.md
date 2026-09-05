# Experiment Tracking & Evidence Storage

## Directory Layout
Every experiment run produces an immutable directory:
```
evidence/experiments/<experiment_id>/
├── manifest.json       # Immutable metadata and SHA-256 artifact hashes
├── hypothesis.md       # Target research question and falsification criteria
├── configuration.json  # Exact solver parameters and round counts
├── conclusion.md       # Outcome, classification, and failure reasons
├── artifacts/          # Output CNF files, logs, and trace dumps
└── verification/       # Independent verification transcripts
```

## Immutable Manifest Format (`manifest.json`)
```json
{
  "experiment_id": "exp_reduced_20260905_181911_126_e46a",
  "parent_experiment": "",
  "start_time": "2026-09-05T18:00:00Z",
  "end_time": "2026-09-05T18:05:00Z",
  "outcome_success": true,
  "classification": "ReducedRoundPreimageVerified",
  "verification": {
    "is_valid": true,
    "actual_rounds": 10,
    "digest_a": "30b5035950f51c6423c51413da9c10a937b956771f8036f57ee8c7006680c686",
    "digest_b": "30b5035950f51c6423c51413da9c10a937b956771f8036f57ee8c7006680c686"
  },
  "artifacts": []
}
```

## Database Storage
Experiment metrics and classifications are mirrored to `evidence/knowledge_base.sqlite` to facilitate automated cross-run queries, trend analysis, and regression detection.
