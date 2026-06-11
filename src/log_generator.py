"""
log_generator.py
Generates synthetic security log entries that mimic real-world
network/system logs seen in a SOC environment.

Log fields are inspired by common SIEM sources:
  - Windows Event Logs
  - Linux auth/syslog
  - Firewall/network logs
  - Web server access logs
"""

import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path


# ── Sample data pools ──────────────────────────────────────────────────────

USERS = [
    "alice", "bob", "charlie", "diana", "eve",
    "frank", "grace", "henry", "ivan", "judy",
    "admin", "root", "service_account", "svc_backup",
]

INTERNAL_IPS = [f"192.168.{random.randint(1,5)}.{random.randint(1,254)}" for _ in range(30)]
EXTERNAL_IPS = [f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}" for _ in range(50)]

EVENT_TYPES = [
    "login_success", "login_failure", "logout",
    "file_access", "file_modified", "file_deleted",
    "process_created", "network_connection",
    "privilege_escalation", "policy_change",
    "service_started", "service_stopped",
    "firewall_block", "dns_query",
]

SEVERITY_LEVELS = ["low", "medium", "high", "critical"]

COUNTRIES = ["NZ", "NZ", "NZ", "AU", "US", "GB", "CN", "RU", "KP", "BR"]

PROCESSES = [
    "explorer.exe", "chrome.exe", "svchost.exe", "powershell.exe",
    "cmd.exe", "python.exe", "bash", "ssh", "curl", "wget",
    "mimikatz.exe", "nc.exe", "nmap",   # suspicious ones
]

PORTS = [22, 80, 443, 3389, 445, 8080, 8443, 4444, 1337, 9001]


def _random_timestamp(start: datetime, end: datetime) -> str:
    delta = end - start
    random_seconds = random.randint(0, int(delta.total_seconds()))
    return (start + timedelta(seconds=random_seconds)).isoformat()


def generate_normal_log(timestamp: str) -> dict:
    """Generate a normal (benign) log entry."""
    return {
        "timestamp": timestamp,
        "user": random.choice(USERS[:10]),            # normal users
        "source_ip": random.choice(INTERNAL_IPS),
        "dest_ip": random.choice(INTERNAL_IPS),
        "event_type": random.choice(EVENT_TYPES[:10]),  # non-suspicious events
        "process": random.choice(PROCESSES[:8]),
        "port": random.choice([80, 443, 22]),
        "bytes_sent": random.randint(100, 5000),
        "bytes_recv": random.randint(200, 10000),
        "duration_sec": round(random.uniform(0.1, 30.0), 2),
        "login_attempts": 1,
        "failed_logins": 0,
        "country": "NZ",
        "is_admin": 0,
        "after_hours": 0,        # 0 = normal business hours
        "label": 0,              # 0 = normal
    }


def generate_anomaly_log(timestamp: str) -> dict:
    """Generate an anomalous (suspicious) log entry."""
    anomaly_type = random.choice([
        "brute_force", "data_exfil", "lateral_movement",
        "privilege_escalation", "c2_beacon", "off_hours_access"
    ])

    base = {
        "timestamp": timestamp,
        "user": random.choice(USERS),
        "source_ip": random.choice(EXTERNAL_IPS),
        "dest_ip": random.choice(INTERNAL_IPS),
        "event_type": random.choice(EVENT_TYPES),
        "process": random.choice(PROCESSES),
        "port": random.choice(PORTS),
        "bytes_sent": 0,
        "bytes_recv": 0,
        "duration_sec": 0,
        "login_attempts": 1,
        "failed_logins": 0,
        "country": random.choice(["CN", "RU", "KP", "US"]),
        "is_admin": 0,
        "after_hours": 0,
        "label": 1,              # 1 = anomaly
    }

    # Tweak values based on anomaly type
    if anomaly_type == "brute_force":
        base["login_attempts"] = random.randint(20, 200)
        base["failed_logins"] = base["login_attempts"] - random.randint(0, 2)
        base["event_type"] = "login_failure"

    elif anomaly_type == "data_exfil":
        base["bytes_sent"] = random.randint(500_000, 5_000_000)
        base["bytes_recv"] = random.randint(100, 500)
        base["duration_sec"] = round(random.uniform(300, 3600), 2)
        base["port"] = random.choice([443, 8443, 4444])

    elif anomaly_type == "lateral_movement":
        base["source_ip"] = random.choice(INTERNAL_IPS)
        base["event_type"] = "network_connection"
        base["port"] = random.choice([445, 3389, 22])
        base["login_attempts"] = random.randint(5, 30)

    elif anomaly_type == "privilege_escalation":
        base["event_type"] = "privilege_escalation"
        base["is_admin"] = 1
        base["process"] = random.choice(["mimikatz.exe", "powershell.exe", "cmd.exe"])

    elif anomaly_type == "c2_beacon":
        base["bytes_sent"] = random.randint(50, 300)
        base["bytes_recv"] = random.randint(50, 300)
        base["duration_sec"] = round(random.uniform(0.5, 2.0), 2)
        base["port"] = random.choice([4444, 1337, 9001])

    elif anomaly_type == "off_hours_access":
        base["after_hours"] = 1
        base["is_admin"] = random.choice([0, 1])
        base["user"] = random.choice(["admin", "root", "service_account"])

    return base


def generate_dataset(
    n_normal: int = 9000,
    n_anomaly: int = 1000,
    output_path: str = "data/sample_logs.csv",
) -> pd.DataFrame:
    """
    Generate a mixed dataset of normal and anomalous log entries.
    Default ratio: ~90% normal, 10% anomalous (realistic SIEM ratio).
    """
    end = datetime.now()
    start = end - timedelta(days=30)

    normal_logs = [
        generate_normal_log(_random_timestamp(start, end))
        for _ in range(n_normal)
    ]
    anomaly_logs = [
        generate_anomaly_log(_random_timestamp(start, end))
        for _ in range(n_anomaly)
    ]

    df = pd.DataFrame(normal_logs + anomaly_logs)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle

    Path(output_path).parent.mkdir(exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"Generated {len(df):,} log entries → {output_path}")
    return df


def generate_live_log(n: int = 1) -> list[dict]:
    """
    Generate n 'live' log entries (used by the dashboard for streaming).
    ~90% normal, ~10% anomalous.
    """
    now = datetime.now().isoformat()
    logs = []
    for _ in range(n):
        if random.random() < 0.10:
            logs.append(generate_anomaly_log(now))
        else:
            logs.append(generate_normal_log(now))
    return logs


if __name__ == "__main__":
    generate_dataset()