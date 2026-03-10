import re
from security.utils import load_config


class RuleResult:
    def __init__(self, rule_name, triggered, severity=0, confidence=1.0, detail=""):
        self.rule_name = rule_name
        self.triggered = triggered
        self.severity = severity
        self.confidence = confidence
        self.detail = detail

    def to_dict(self):
        return {
            "rule_name": self.rule_name,
            "triggered": self.triggered,
            "severity": self.severity,
            "confidence": self.confidence,
            "detail": self.detail,
        }


class RuleEngine:
    """
    Evaluates MQTT packets against a set of detection rules.
    Each rule returns a severity (0-10) and confidence (0.0-1.0).
    """

    def __init__(self):
        self.detection_rules = load_config("detection_rules.json")
        self.mqtt_topics = load_config("mqtt_topics.json")
        self.value_ranges = self.detection_rules["value_ranges"]
        self.topic_acl = self.detection_rules["topic_acl"]
        self.severity_thresholds = self.detection_rules["severity_thresholds"]
        self.escalation = self.detection_rules["llm_escalation_threshold"]

        self._topic_to_device = self.mqtt_topics.get("topic_to_device_map", {})
        self._all_sensor_topics = set(self.mqtt_topics.get("sensor_topics", {}).values())
        self._all_actuator_topics = set(self.mqtt_topics.get("actuator_topics", {}).values())
        self._all_security_topics = set(self.mqtt_topics.get("security_topics", {}).values())

    def evaluate(self, packet):
        """
        Run all rules on a PacketRecord.
        Returns (triggered_rules, total_severity, min_confidence, needs_llm).
        """
        results = []
        results.append(self._check_value_range(packet))
        results.append(self._check_topic_acl(packet))
        results.append(self._check_payload_integrity(packet))
        results.append(self._check_direct_actuator_access(packet))
        results.append(self._check_unknown_topic(packet))
        results.append(self._check_suspicious_patterns(packet))

        triggered = [r for r in results if r.triggered]
        if not triggered:
            return [], 0, 1.0, False

        total_severity = max(r.severity for r in triggered)
        min_confidence = min(r.confidence for r in triggered)
        needs_llm = (
            total_severity >= self.escalation["min_severity"]
            and min_confidence <= self.escalation["max_confidence"]
        )

        return (
            [r.to_dict() for r in triggered],
            total_severity,
            min_confidence,
            needs_llm,
        )

    def _check_value_range(self, packet):
        """Check if sensor payload falls within expected value ranges."""
        topic = packet.topic

        sensor_name = None
        for name, rule in self.value_ranges.items():
            if rule.get("topic") == topic:
                sensor_name = name
                break

        if sensor_name is None:
            return RuleResult("value_range", False)

        rule = self.value_ranges[sensor_name]
        payload = packet.payload.strip()

        if rule["type"] == "enum":
            if payload not in rule["allowed_values"]:
                return RuleResult(
                    "value_range",
                    True,
                    severity=8,
                    confidence=0.9,
                    detail=f"Value '{payload}' not in allowed set {rule['allowed_values']} for {sensor_name}",
                )
        elif rule["type"] == "numeric":
            try:
                val = float(payload)
                if val < rule["min"] or val > rule["max"]:
                    severity = 7 if abs(val) < 1000 else 9
                    return RuleResult(
                        "value_range",
                        True,
                        severity=severity,
                        confidence=0.85,
                        detail=f"Value {val} outside range [{rule['min']}, {rule['max']}] for {sensor_name}",
                    )
            except ValueError:
                return RuleResult(
                    "value_range",
                    True,
                    severity=6,
                    confidence=0.7,
                    detail=f"Non-numeric value '{payload}' for numeric sensor {sensor_name}",
                )

        return RuleResult("value_range", False)

    def _check_topic_acl(self, packet):
        """Check if the publishing client is authorized for this topic."""
        topic = packet.topic
        client_id = packet.client_id

        if topic.startswith("security/"):
            return RuleResult("topic_acl", False)

        allowed_devices = self.topic_acl.get(topic)
        if allowed_devices is None:
            return RuleResult("topic_acl", False)

        device_key = self._client_id_to_device_key(client_id)
        if device_key and device_key not in allowed_devices:
            return RuleResult(
                "topic_acl",
                True,
                severity=8,
                confidence=0.9,
                detail=f"Client '{client_id}' (device: {device_key}) not authorized for topic '{topic}'. Allowed: {allowed_devices}",
            )

        return RuleResult("topic_acl", False)

    def _check_payload_integrity(self, packet):
        """Check for malformed, binary, or suspicious payload content."""
        payload = packet.payload

        if not payload or payload.strip() == "":
            return RuleResult(
                "payload_integrity",
                True,
                severity=4,
                confidence=0.8,
                detail="Empty payload detected",
            )

        suspicious_patterns = [
            (r"[\x00-\x08\x0e-\x1f]", "Binary/control characters in payload"),
            (r"(?i)(select|insert|update|delete|drop|union)\s", "SQL injection pattern"),
            (r"<script", "XSS script injection pattern"),
            (r"\.\./\.\.", "Path traversal pattern"),
            (r"\\x[0-9a-fA-F]{2}", "Hex escape sequences"),
        ]

        for pattern, description in suspicious_patterns:
            if re.search(pattern, payload):
                return RuleResult(
                    "payload_integrity",
                    True,
                    severity=7,
                    confidence=0.6,
                    detail=f"{description} in payload: '{payload[:80]}'",
                )

        return RuleResult("payload_integrity", False)

    def _check_direct_actuator_access(self, packet):
        """Detect non-CPU clients publishing to actuator control topics."""
        if packet.topic not in self._all_actuator_topics:
            return RuleResult("direct_actuator_access", False)

        if packet.client_id == "cpu-controller" or packet.client_id == "ids-node":
            return RuleResult("direct_actuator_access", False)

        return RuleResult(
            "direct_actuator_access",
            True,
            severity=9,
            confidence=0.95,
            detail=f"Non-CPU client '{packet.client_id}' publishing to actuator topic '{packet.topic}'",
        )

    def _check_unknown_topic(self, packet):
        """Flag messages on topics not in the known registry."""
        topic = packet.topic
        all_known = (
            self._all_sensor_topics
            | self._all_actuator_topics
            | self._all_security_topics
        )

        if topic.startswith("home/") and topic.endswith("/ack"):
            return RuleResult("unknown_topic", False)

        if topic not in all_known:
            return RuleResult(
                "unknown_topic",
                True,
                severity=5,
                confidence=0.5,
                detail=f"Message on unregistered topic: '{topic}'",
            )

        return RuleResult("unknown_topic", False)

    def _check_suspicious_patterns(self, packet):
        """Heuristic checks for anomalous behavior patterns."""
        payload = packet.payload

        if len(payload) > 500:
            return RuleResult(
                "suspicious_pattern",
                True,
                severity=5,
                confidence=0.4,
                detail=f"Unusually large payload ({len(payload)} chars) for IoT message",
            )

        if payload == payload[:1] * len(payload) and len(payload) > 10:
            return RuleResult(
                "suspicious_pattern",
                True,
                severity=6,
                confidence=0.5,
                detail=f"Repeated character pattern in payload (possible flooding data)",
            )

        return RuleResult("suspicious_pattern", False)

    def _client_id_to_device_key(self, client_id):
        """Map an MQTT client ID back to a device key in network config."""
        if client_id == "cpu-controller":
            return "cpu"
        if client_id == "ids-node":
            return "ids-node"
        if client_id.endswith("-sensor"):
            name = client_id.replace("-sensor", "")
            for key, dev in self._get_devices().items():
                if dev.get("name") == name and dev.get("type") == "sensor":
                    return key
        if client_id.endswith("-actuator"):
            name = client_id.replace("-actuator", "")
            for key, dev in self._get_devices().items():
                if dev.get("name") == name and dev.get("type") == "actuator":
                    return key
        return client_id

    def _get_devices(self):
        try:
            config = load_config("network_config.json")
            return config.get("devices", {})
        except Exception:
            return {}
