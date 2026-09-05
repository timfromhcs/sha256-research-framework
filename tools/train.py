#!/usr/bin/env python3
"""
ML Search Guidance & Differential Trail Ranking Model
Uses PyTorch to train a neural ranker / score estimator for differential trails in SHA-256.
"""

import os
import json
import random
import sqlite3
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

class TrailRanker(nn.Module):
    """
    MLP model scoring the empirical survivability / propagation quality
    of a differential trail candidate in reduced-round SHA-256.
    """
    def __init__(self, input_dim=16, hidden_dim=64):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.1),
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Linear(hidden_dim // 2, 1)
        )

    def forward(self, x):
        return self.net(x)

def generate_synthetic_trail_features(num_samples=1000):
    """
    Features representing trail properties:
    - Active bits per round (rounds 0..7)
    - Total conditions count
    - Estimated log2 probability
    - Message difference Hamming weight
    """
    X = []
    y = []
    for _ in range(num_samples):
        # 8 round active bit counts
        active_bits = np.random.poisson(lam=3.0, size=8).astype(np.float32)
        conditions = float(np.random.randint(0, 30))
        msg_weight = float(np.random.randint(1, 15))
        log2_prob = -float(np.sum(active_bits) * 0.8 + conditions * 0.3)
        
        # 16 features: 8 active bit counts, conditions, msg_weight, log2_prob, 5 summary stats
        feats = list(active_bits) + [
            conditions,
            msg_weight,
            log2_prob,
            float(np.mean(active_bits)),
            float(np.max(active_bits)),
            float(np.min(active_bits)),
            float(np.std(active_bits)),
            float(np.sum(active_bits))
        ]
        # Ground truth score (survivability): lower penalty = higher score
        score = -log2_prob - (conditions * 0.5) - (msg_weight * 0.2) + np.random.normal(0, 0.5)
        X.append(feats)
        y.append([score])

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.float32)

def train_model():
    print("===============================================================")
    print("      Training ML Search Guidance Model for SHA-256 Trails     ")
    print("===============================================================")

    os.makedirs("ml/models", exist_ok=True)
    os.makedirs("ml/datasets", exist_ok=True)

    X, y = generate_synthetic_trail_features(2000)

    # Train / Val / Test Split: 70% / 15% / 15%
    n = len(X)
    n_train = int(0.7 * n)
    n_val = int(0.15 * n)

    X_train, y_train = torch.tensor(X[:n_train]), torch.tensor(y[:n_train])
    X_val, y_val = torch.tensor(X[n_train:n_train+n_val]), torch.tensor(y[n_train:n_train+n_val])
    X_test, y_test = torch.tensor(X[n_train+n_val:]), torch.tensor(y[n_train+n_val:])

    model = TrailRanker(input_dim=16, hidden_dim=64)
    criterion = nn.MSELoss()
    optimizer = optim.AdamW(model.parameters(), lr=0.005, weight_decay=1e-4)

    best_val_loss = float('inf')
    epochs = 40

    for epoch in range(epochs):
        model.train()
        optimizer.zero_grad()
        preds = model(X_train)
        loss = criterion(preds, y_train)
        loss.backward()
        optimizer.step()

        model.eval()
        with torch.no_grad():
            val_preds = model(X_val)
            val_loss = criterion(val_preds, y_val).item()

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            torch.save(model.state_dict(), "ml/models/trail_ranker.pt")

    # Final evaluation on test set
    model.load_state_dict(torch.load("ml/models/trail_ranker.pt"))
    model.eval()
    with torch.no_grad():
        test_preds = model(X_test)
        test_mse = criterion(test_preds, y_test).item()
        test_mae = torch.mean(torch.abs(test_preds - y_test)).item()

    # Compare against non-ML baseline (simple linear heuristic: -log2_prob)
    baseline_preds = X_test[:, 10:11] # log2_prob column inverted
    baseline_mse = criterion(-baseline_preds, y_test).item()

    metrics = {
        "dataset_size": n,
        "train_size": n_train,
        "val_size": n_val,
        "test_size": len(X_test),
        "best_val_loss": best_val_loss,
        "test_mse": test_mse,
        "test_mae": test_mae,
        "baseline_heuristic_mse": baseline_mse,
        "improvement_pct": ((baseline_mse - test_mse) / baseline_mse) * 100.0,
        "device": "cpu",
        "pytorch_version": torch.__version__
    }

    with open("ml/models/metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"Training complete! Test MSE: {test_mse:.4f} (Baseline Heuristic: {baseline_mse:.4f})")
    print(f"Model saved to ml/models/trail_ranker.pt")
    print(f"Metrics saved to ml/models/metrics.json")
    return 0

if __name__ == "__main__":
    train_model()
