"""
alert_engine.py
Converts raw anomaly scores into actionable SIEM alerts.
Applies a rule layer on top of the risk score for context.
"""

from datetime import datetime


SEVERITY_THRESHOLDS = {
    "critical": 0.85,
    "high":     0.70,
    "medium":   0.55,
    "low":      0.40,
}

ALERT_RULES = [
    {
        "name": "Brute Force Detected",
        "condition": lambda f: f.get("failed_logins", 0) > 10,
        "severity": "high",
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110",
    },
    {
        "name": "Data Exfiltration Suspected",
        "condition": lambda f: f.get("bytes_sent", 0) > 200_000,
        "severity": "critical",
        "mitre_tactic": "Exfiltration",
        "mitre_technique": "T1041",
    },
    {
        "name": "High-Risk Port Activity",
        "condition": lambda f: f.get("is_high_risk_port", 0) == 1,
        "severity": "high",
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1095",
    },
    {
        "name": "Suspicious Process Executed",
        "condition": lambda f: f.get("is_suspicious_process", 0) == 1,
        "severity": "critical",
        "mitre_tactic": "Execution",
        "mitre_technique": "T1059",
    },
    {
        "name": "Privilege Escalation",
        "condition": lambda f: f.get("is_admin", 0) == 1 and f.get("after_hours_flag", 0) == 1,
        "severity": "critical",
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1068",
    },
    {
        "name": "After-Hours Admin Access",
        "condition": lambda f: f.get("is_after_hours", 0) == 1 and f.get("is_admin", 0) == 1,
        "severity": "medium",
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1078",
    },
    {
        "name": "High Country Risk",
        "condition": lambda f: f.get("country_risk_score", 0) >= 3,
        "severity": "medium",
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190",
    },
    {
        "name": "Lateral Movement Attempt",
        "condition": lambda f: f.get("is_lateral_port", 0) == 1 and f.get("is_internal_source", 1) == 1,
        "severity": "high",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021",
    },
]


def _score_to_severity(score: float) -> str:
    for sev, threshold in SEVERITY_THRESHOLDS.items():
        if score >= threshold:
            return sev
    return "info"


def generate_alert(
    log_entry: dict,
    features: dict,
    anomaly_score: float,
    is_anomaly: bool,
) -> dict | None:
    """
    Generate a SIEM alert combining risk scoring with rule-based matching.
    Returns None if the event is not alertable.
    """
    if not is_anomaly and anomaly_score < 0.40:
        return None

    matched_rules = [r for r in ALERT_RULES if r["condition"](features)]
    score_severity = _score_to_severity(anomaly_score)

    # Take the highest severity between the score and any rule match.
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    rule_severity = max(
        [r["severity"] for r in matched_rules],
        key=lambda s: severity_rank[s],
        default="low",
    )

    final_severity = max(score_severity, rule_severity, key=lambda s: severity_rank[s])

    return {
        "alert_id": f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S%f')[:18]}",
        "timestamp": log_entry.get("timestamp", datetime.now().isoformat()),
        "user": log_entry.get("user", "unknown"),
        "source_ip": log_entry.get("source_ip", ""),
        "event_type": log_entry.get("event_type", ""),
        "severity": final_severity,
        "risk_score": round(anomaly_score, 4),
        "is_outlier": is_anomaly,
        "matched_rules": [r["name"] for r in matched_rules],
        "mitre_tactics": list({r["mitre_tactic"] for r in matched_rules}),
        "mitre_techniques": list({r["mitre_technique"] for r in matched_rules}),
        "description": matched_rules[0]["name"] if matched_rules else "Unusual Activity Detected",
    }
