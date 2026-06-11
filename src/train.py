"""
train.py
Generates data, extracts features, trains the Isolation Forest,
and prints evaluation stats.
"""

import os
import pandas as pd
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

from src.log_generator import generate_dataset
from src.feature_engineering import extract_features_batch
from src.anomaly_detector import train_model, predict

load_dotenv()

console = Console()

DATA_PATH = os.getenv("TRAIN_DATA_PATH", "data/sample_logs.csv")
MODEL_PATH = os.getenv("MODEL_PATH", "models/siem_model.joblib")


def train():
    # ── 1. Generate or load data ─────────────────────────────────────────
    console.print("[bold cyan]Step 1: Generating synthetic log data...[/bold cyan]")
    df = generate_dataset(n_normal=9000, n_anomaly=1000, output_path=DATA_PATH)

    # ── 2. Feature engineering ───────────────────────────────────────────
    console.print("[bold cyan]Step 2: Extracting features...[/bold cyan]")
    X = extract_features_batch(df)
    y_true = df["label"].values   # 0=normal, 1=anomaly (for evaluation only)
    console.print(f"Feature matrix: {X.shape}")

    # ── 3. Train on ALL data (unsupervised) ──────────────────────────────
    # Isolation Forest is unsupervised — labels are NOT used for training.
    # We use them only to evaluate how well it detected the injected anomalies.
    console.print("[bold cyan]Step 3: Training Isolation Forest...[/bold cyan]")
    model = train_model(X, save_path=MODEL_PATH)

    # ── 4. Evaluate ──────────────────────────────────────────────────────
    console.print("[bold cyan]Step 4: Evaluating detection performance...[/bold cyan]")
    results = predict(model, X)

    # IsolationForest returns -1 for anomaly, 1 for normal
    # Our labels: 1=anomaly, 0=normal — convert for comparison
    predicted_anomaly = (results["predictions"] == -1).astype(int)

    tp = int(((predicted_anomaly == 1) & (y_true == 1)).sum())
    fp = int(((predicted_anomaly == 1) & (y_true == 0)).sum())
    tn = int(((predicted_anomaly == 0) & (y_true == 0)).sum())
    fn = int(((predicted_anomaly == 0) & (y_true == 1)).sum())

    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * precision * recall / max(precision + recall, 0.001)

    table = Table(title="Anomaly Detection Evaluation")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("True Positives (detected anomalies)", str(tp))
    table.add_row("False Positives (false alarms)", str(fp))
    table.add_row("True Negatives (correct normal)", str(tn))
    table.add_row("False Negatives (missed anomalies)", str(fn))
    table.add_row("Precision", f"{precision:.3f}")
    table.add_row("Recall", f"{recall:.3f}")
    table.add_row("F1 Score", f"{f1:.3f}")

    console.print(table)
    console.print(f"[bold green]Training complete. Model saved to {MODEL_PATH}[/bold green]")


if __name__ == "__main__":
    train()