"""
test_alerts.py — Unit tests for the alert engine
"""
import pytest
from src.alert_engine import generate_alert, _score_to_severity


NORMAL_LOG = {
    "timestamp": "2026-06-01T10:00:00",
    "user": "alice",
    "source_ip": "192.168.1.10",
    "event_type": "login_success",
}

NORMAL_FEATURES = {
    "failed_logins": 0,
    "login_attempts": 1,
    "failure_ratio": 0.0,
    "bytes_sent": 500,
    "is_high_risk_port": 0,
    "is_suspicious_process": 0,
    "is_admin": 0,
    "after_hours_flag": 0,
    "is_after_hours": 0,
    "country_risk_score": 0,
    "is_lateral_port": 0,
    "is_internal_source": 1,
}

ANOMALY_FEATURES = {
    **NORMAL_FEATURES,
    "failed_logins": 50,
    "login_attempts": 55,
    "failure_ratio": 0.91,
    "bytes_sent": 3_000_000,
    "is_high_risk_port": 1,
    "is_suspicious_process": 1,
    "country_risk_score": 4,
}


class TestSeverityScoring:
    def test_critical(self):
        assert _score_to_severity(0.90) == "critical"

    def test_high(self):
        assert _score_to_severity(0.75) == "high"

    def test_info(self):
        assert _score_to_severity(0.10) == "info"


class TestAlertGeneration:
    def test_no_alert_for_normal(self):
        alert = generate_alert(NORMAL_LOG, NORMAL_FEATURES, 0.10, False)
        assert alert is None

    def test_alert_for_anomaly(self):
        alert = generate_alert(NORMAL_LOG, ANOMALY_FEATURES, 0.90, True)
        assert alert is not None
        assert alert["severity"] in ("critical", "high")

    def test_alert_has_required_fields(self):
        alert = generate_alert(NORMAL_LOG, ANOMALY_FEATURES, 0.90, True)
        for field in ["alert_id", "severity", "risk_score", "mitre_tactics"]:
            assert field in alert

    def test_brute_force_rule(self):
        features = {**NORMAL_FEATURES, "failed_logins": 50, "login_attempts": 55, "failure_ratio": 0.91}
        alert = generate_alert(NORMAL_LOG, features, 0.75, True)
        assert "Brute Force Detected" in alert["matched_rules"]
