"""
feature_engineering.py
Converts raw log entry dicts/DataFrames into numeric feature matrices.
The Isolation Forest works on purely numeric input — this module handles
all encoding and derived features.
"""

import pandas as pd
import numpy as np
from datetime import datetime


# ── Encoding maps ──────────────────────────────────────────────────────────

EVENT_TYPE_ENCODING = {
    "login_success": 0, "login_failure": 1, "logout": 2,
    "file_access": 3, "file_modified": 4, "file_deleted": 5,
    "process_created": 6, "network_connection": 7,
    "privilege_escalation": 8, "policy_change": 9,
    "service_started": 10, "service_stopped": 11,
    "firewall_block": 12, "dns_query": 13,
}

COUNTRY_RISK = {
    "NZ": 0, "AU": 1, "US": 1, "GB": 1,
    "CN": 3, "RU": 3, "KP": 4, "BR": 2,
}

SUSPICIOUS_PROCESSES = {
    "mimikatz.exe", "nc.exe", "nmap", "netcat",
    "meterpreter", "beacon.exe",
}

HIGH_RISK_PORTS = {4444, 1337, 9001, 31337, 6666}
LATERAL_PORTS = {445, 3389, 22, 135, 139}


def _ip_to_int(ip: str) -> int:
    """Convert IP string to an integer approximation."""
    try:
        parts = ip.split(".")
        return int(parts[0]) * 256**3 + int(parts[1]) * 256**2 + \
               int(parts[2]) * 256 + int(parts[3])
    except Exception:
        return 0


def _is_internal_ip(ip: str) -> int:
    return int(ip.startswith("192.168.") or
               ip.startswith("10.") or
               ip.startswith("172."))


def _hour_of_day(timestamp: str) -> int:
    """Extract hour from ISO timestamp."""
    try:
        return datetime.fromisoformat(timestamp).hour
    except Exception:
        return 12


def _is_suspicious_process(process: str) -> int:
    return int(process.lower() in SUSPICIOUS_PROCESSES)


def _is_high_risk_port(port: int) -> int:
    return int(port in HIGH_RISK_PORTS)


def _is_lateral_port(port: int) -> int:
    return int(port in LATERAL_PORTS)


def extract_features_from_row(row: dict) -> dict:
    """
    Extract numeric features from a single log entry dict.
    """
    hour = _hour_of_day(row.get("timestamp", ""))
    failed = row.get("failed_logins", 0)
    attempts = max(row.get("login_attempts", 1), 1)
    bytes_sent = row.get("bytes_sent", 0)
    bytes_recv = row.get("bytes_recv", 1)

    return {
        # Event metadata
        "event_type_encoded": EVENT_TYPE_ENCODING.get(
            row.get("event_type", ""), -1
        ),
        "hour_of_day": hour,
        "is_after_hours": int(hour < 6 or hour > 22),
        "after_hours_flag": row.get("after_hours", 0),

        # Auth patterns
        "login_attempts": attempts,
        "failed_logins": failed,
        "failure_ratio": round(failed / attempts, 4),
        "is_brute_force": int(attempts > 10),

        # Network features
        "bytes_sent": bytes_sent,
        "bytes_recv": bytes_recv,
        "bytes_ratio": round(bytes_sent / max(bytes_recv, 1), 4),
        "total_bytes": bytes_sent + bytes_recv,
        "duration_sec": row.get("duration_sec", 0),
        "port": row.get("port", 80),
        "is_high_risk_port": _is_high_risk_port(row.get("port", 80)),
        "is_lateral_port": _is_lateral_port(row.get("port", 80)),

        # IP intelligence
        "source_ip_int": _ip_to_int(row.get("source_ip", "0.0.0.0")),
        "is_internal_source": _is_internal_ip(row.get("source_ip", "")),
        "country_risk_score": COUNTRY_RISK.get(row.get("country", "NZ"), 2),

        # Process intelligence
        "is_suspicious_process": _is_suspicious_process(
            row.get("process", "")
        ),

        # Privilege
        "is_admin": row.get("is_admin", 0),
    }


def extract_features_batch(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract features from a full DataFrame of log entries.
    """
    records = [extract_features_from_row(row) for row in df.to_dict("records")]
    return pd.DataFrame(records)


# Feature columns for downstream use
FEATURE_COLUMNS = list(extract_features_from_row({}).keys())
