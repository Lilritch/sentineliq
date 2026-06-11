"""
anomaly_detector.py
Wraps sklearn's IsolationForest for SIEM anomaly detection.

Why Isolation Forest?
- Unsupervised: no labelled data required (perfect for log analysis)
- Fast on high-dimensional data
- Robust to noisy features
- Common baseline for SIEM anomaly scoring
"""

import os
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from dotenv import load_dotenv
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

load_dotenv()

MODEL_PATH = os.getenv("MODEL_PATH", "models/siem_model.joblib")
CONTAMINATION = float(os.getenv("ANOMALY_CONTAMINATION", 0.05))


def build_model(contamination: float = CONTAMINATION) -> Pipeline:
    """Build the Isolation Forest pipeline."""
    return Pipeline([
        ("scaler", StandardScaler()),
        ("detector", IsolationForest(
            n_estimators=200,
            contamination=contamination,
            max_samples="auto",
            bootstrap=False,
            n_jobs=-1,
            random_state=42,
            verbose=0,
        )),
    ])


def train_model(X: pd.DataFrame, save_path: str = MODEL_PATH) -> Pipeline:
    """Fit Isolation Forest on normal log features and save."""
    model = build_model()
    model.fit(X)
    Path(save_path).parent.mkdir(exist_ok=True)
    joblib.dump(model, save_path)
    print(f"Model saved → {save_path}")
    return model


def load_model(path: str = MODEL_PATH) -> Pipeline:
    """Load saved model from disk."""
    return joblib.load(path)


def predict(model: Pipeline, X: pd.DataFrame) -> dict:
    """
    Run anomaly detection on feature matrix X.

    Returns dict with:
      - predictions: array of 1 (normal) or -1 (anomaly)
      - scores: raw anomaly scores (more negative = more anomalous)
      - anomaly_flags: boolean array
      - anomaly_probability: normalised 0-1 score (higher = more anomalous)
    """
    raw_scores = model.decision_function(X)       # negative = anomalous
    predictions = model.predict(X)                # 1 or -1

    # Normalise scores to 0-1 range (1 = most anomalous)
    min_s, max_s = raw_scores.min(), raw_scores.max()
    if max_s != min_s:
        normalised = 1 - (raw_scores - min_s) / (max_s - min_s)
    else:
        normalised = np.zeros(len(raw_scores))

    return {
        "predictions": predictions,
        "scores": raw_scores,
        "anomaly_flags": predictions == -1,
        "anomaly_probability": normalised,
    }


def predict_single(model: Pipeline, features: dict) -> dict:
    """Predict anomaly score for a single log entry feature dict."""
    df = pd.DataFrame([features])
    result = predict(model, df)
    return {
        "is_anomaly": bool(result["anomaly_flags"][0]),
        "anomaly_score": round(float(result["anomaly_probability"][0]), 4),
        "raw_score": round(float(result["scores"][0]), 4),
    }
