import json
import os
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(SCRIPT_DIR, "..", "config")


def load_config(filename):
    path = os.path.join(CONFIG_DIR, filename)
    with open(path, "r") as f:
        return json.load(f)


def timestamp_now():
    return datetime.now().isoformat()


def timestamp_readable():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def severity_label(score):
    if score >= 9:
        return "CRITICAL"
    elif score >= 7:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    elif score >= 3:
        return "LOW"
    return "INFO"


class PacketRecord:
    """Represents a captured MQTT message with metadata for analysis."""

    def __init__(self, topic, payload, client_id=None, source_ip=None):
        self.topic = topic
        self.payload = payload
        self.client_id = client_id or "unknown"
        self.source_ip = source_ip or "unknown"
        self.timestamp = timestamp_now()
        self.timestamp_readable = timestamp_readable()

    def to_dict(self):
        return {
            "topic": self.topic,
            "payload": self.payload,
            "client_id": self.client_id,
            "source_ip": self.source_ip,
            "timestamp": self.timestamp,
            "timestamp_readable": self.timestamp_readable,
        }

    def __repr__(self):
        return (
            f"PacketRecord(topic={self.topic}, payload={self.payload[:50]}, "
            f"client={self.client_id}, ip={self.source_ip})"
        )


class ThreatEvent:
    """Captures a complete threat incident with all analysis and response data."""

    def __init__(self, packet, rules_triggered, severity, confidence):
        self.id = f"THREAT-{datetime.now().strftime('%Y%m%d%H%M%S%f')}"
        self.packet = packet
        self.rules_triggered = rules_triggered
        self.severity = severity
        self.severity_label = severity_label(severity)
        self.confidence = confidence
        self.timestamp = timestamp_now()
        self.timestamp_readable = timestamp_readable()
        self.llm_analysis = None
        self.decision = None
        self.action_taken = None
        self.healed_at = None

    def to_dict(self):
        return {
            "id": self.id,
            "packet": self.packet.to_dict(),
            "rules_triggered": self.rules_triggered,
            "severity": self.severity,
            "severity_label": self.severity_label,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "timestamp_readable": self.timestamp_readable,
            "llm_analysis": self.llm_analysis,
            "decision": self.decision,
            "action_taken": self.action_taken,
            "healed_at": self.healed_at,
        }
