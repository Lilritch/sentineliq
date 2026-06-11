"""
main.py — FastAPI SIEM backend
Exposes endpoints for log ingestion, event scoring, and alert retrieval.
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import os
import joblib
from dotenv import load_dotenv
from collections import deque
from datetime import datetime

from src.feature_engineering import extract_features_from_row
from src.anomaly_detector import load_model, predict_single
from src.alert_engine import generate_alert
from src.log_generator import generate_live_log

load_dotenv()

app = FastAPI(
    title="SentinelIQ API",
    description="Real-time risk scoring for security log streams.",
    version="1.0.0",
)

# In-memory alert store (replace with a DB in production)
ALERT_STORE: deque = deque(maxlen=1000)
MODEL = None


@app.on_event("startup")
def startup():
    global MODEL
    model_path = os.getenv("MODEL_PATH", "models/siem_model.joblib")
    try:
        MODEL = load_model(model_path)
        print(f"Model loaded from {model_path}")
    except FileNotFoundError:
        print("[WARNING] No model found. Run: python -m src.train")


# ── Schemas ────────────────────────────────────────────────────────────────

class LogEntry(BaseModel):
    timestamp: Optional[str] = None
    user: Optional[str] = "unknown"
    source_ip: Optional[str] = "0.0.0.0"
    dest_ip: Optional[str] = "0.0.0.0"
    event_type: Optional[str] = "network_connection"
    process: Optional[str] = ""
    port: Optional[int] = 80
    bytes_sent: Optional[int] = 0
    bytes_recv: Optional[int] = 0
    duration_sec: Optional[float] = 0.0
    login_attempts: Optional[int] = 1
    failed_logins: Optional[int] = 0
    country: Optional[str] = "NZ"
    is_admin: Optional[int] = 0
    after_hours: Optional[int] = 0


class BatchLogRequest(BaseModel):
    logs: list[LogEntry]


# ── Routes ─────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {
        "status": "running",
        "scoring_ready": MODEL is not None,
        "total_alerts": len(ALERT_STORE),
    }


@app.post("/ingest", tags=["Ingestion"])
def ingest_log(entry: LogEntry):
    """
    Ingest a single log entry, score it, and return the result.
    """
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model not loaded.")

    log_dict = entry.model_dump()
    if not log_dict["timestamp"]:
        log_dict["timestamp"] = datetime.now().isoformat()

    features = extract_features_from_row(log_dict)
    detection = predict_single(MODEL, features)

    alert = generate_alert(
        log_entry=log_dict,
        features=features,
        anomaly_score=detection["anomaly_score"],
        is_anomaly=detection["is_anomaly"],
    )

    if alert:
        ALERT_STORE.appendleft(alert)

    return {
        "log": log_dict,
        "detection": detection,
        "alert": alert,
    }


@app.post("/ingest/batch", tags=["Ingestion"])
def ingest_batch(request: BatchLogRequest):
    """Ingest multiple log entries at once."""
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model not loaded.")

    results = []
    for entry in request.logs:
        log_dict = entry.model_dump()
        if not log_dict["timestamp"]:
            log_dict["timestamp"] = datetime.now().isoformat()
        features = extract_features_from_row(log_dict)
        detection = predict_single(MODEL, features)
        alert = generate_alert(log_dict, features, detection["anomaly_score"], detection["is_anomaly"])
        if alert:
            ALERT_STORE.appendleft(alert)
        results.append({"detection": detection, "alert": alert})

    return {"processed": len(results), "results": results}


@app.get("/alerts", tags=["Alerts"])
def get_alerts(limit: int = 50, severity: Optional[str] = None):
    """Retrieve recent alerts, optionally filtered by severity."""
    alerts = list(ALERT_STORE)
    if severity:
        alerts = [a for a in alerts if a["severity"] == severity]
    return {"count": len(alerts[:limit]), "alerts": alerts[:limit]}


@app.get("/simulate", tags=["Demo"])
def simulate_log():
    """Generate and process a synthetic live log entry (demo mode)."""
    if MODEL is None:
        raise HTTPException(status_code=503, detail="Model not loaded.")

    raw = generate_live_log(1)[0]
    entry = LogEntry(**{k: v for k, v in raw.items() if k != "label"})
    return ingest_log(entry)


@app.delete("/alerts/clear", tags=["Alerts"])
def clear_alerts():
    ALERT_STORE.clear()
    return {"message": "Alert store cleared."}
