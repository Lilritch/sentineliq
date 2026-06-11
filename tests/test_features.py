"""
test_features.py — Unit tests for feature engineering
"""
import pytest
from src.feature_engineering import (
    extract_features_from_row,
    _ip_to_int,
    _is_internal_ip,
    _is_suspicious_process,
    _is_high_risk_port,
)


SAMPLE_NORMAL = {
    "timestamp": "2026-06-01T10:00:00",
    "user": "alice",
    "source_ip": "192.168.1.10",
    "dest_ip": "192.168.1.20",
    "event_type": "login_success",
    "process": "explorer.exe",
    "port": 443,
    "bytes_sent": 1000,
    "bytes_recv": 5000,
    "duration_sec": 5.0,
    "login_attempts": 1,
    "failed_logins": 0,
    "country": "NZ",
    "is_admin": 0,
    "after_hours": 0,
}

SAMPLE_ANOMALY = {
    **SAMPLE_NORMAL,
    "source_ip": "195.22.100.5",
    "process": "mimikatz.exe",
    "port": 4444,
    "bytes_sent": 2_000_000,
    "failed_logins": 50,
    "login_attempts": 55,
    "country": "RU",
    "is_admin": 1,
    "after_hours": 1,
}


class TestIPFunctions:
    def test_internal_ip(self):
        assert _is_internal_ip("192.168.1.1") == 1

    def test_external_ip(self):
        assert _is_internal_ip("8.8.8.8") == 0

    def test_ip_to_int(self):
        assert _ip_to_int("192.168.1.1") > 0


class TestProcessDetection:
    def test_suspicious_process(self):
        assert _is_suspicious_process("mimikatz.exe") == 1

    def test_normal_process(self):
        assert _is_suspicious_process("chrome.exe") == 0


class TestPortDetection:
    def test_high_risk_port(self):
        assert _is_high_risk_port(4444) == 1

    def test_normal_port(self):
        assert _is_high_risk_port(443) == 0


class TestFeatureExtraction:
    def test_returns_dict(self):
        result = extract_features_from_row(SAMPLE_NORMAL)
        assert isinstance(result, dict)

    def test_normal_low_risk(self):
        result = extract_features_from_row(SAMPLE_NORMAL)
        assert result["failure_ratio"] == 0.0
        assert result["country_risk_score"] == 0
        assert result["is_suspicious_process"] == 0

    def test_anomaly_high_risk(self):
        result = extract_features_from_row(SAMPLE_ANOMALY)
        assert result["failure_ratio"] > 0.5
        assert result["country_risk_score"] == 3
        assert result["is_suspicious_process"] == 1
        assert result["is_high_risk_port"] == 1
        assert result["is_admin"] == 1