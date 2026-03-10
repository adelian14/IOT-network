import json
from datetime import datetime
from security.utils import ThreatEvent, severity_label, timestamp_now


class DecisionEngine:
    """
    Combines rule engine verdicts and optional LLM analysis to produce a
    final decision (SAFE / SUSPICIOUS / THREAT) and generate self-healing
    actions for the CPU.
    """

    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    THREAT = "THREAT"

    def __init__(self, mqtt_client, report_generator=None):
        self.mqtt_client = mqtt_client
        self.report_generator = report_generator
        self.incident_log = []

    def decide(self, packet, rules_triggered, severity, confidence, llm_result=None):
        """
        Produce a verdict and, for threats, publish self-healing actions.
        Returns (verdict, threat_event_or_None).
        """
        if not rules_triggered:
            return self.SAFE, None

        if llm_result and llm_result.get("is_threat") is False:
            severity = max(0, severity - 3)
            confidence = max(confidence, llm_result.get("confidence", confidence))

        if llm_result and llm_result.get("is_threat") is True:
            llm_level = llm_result.get("threat_level", "medium")
            llm_severity_map = {"critical": 10, "high": 8, "medium": 6, "low": 3, "none": 0}
            llm_sev = llm_severity_map.get(llm_level, 5)
            severity = max(severity, llm_sev)
            confidence = max(confidence, llm_result.get("confidence", 0.5))

        if severity >= 7:
            verdict = self.THREAT
        elif severity >= 4:
            verdict = self.SUSPICIOUS
        else:
            verdict = self.SAFE

        if verdict == self.SAFE:
            return verdict, None

        threat = ThreatEvent(packet, rules_triggered, severity, confidence)
        threat.llm_analysis = llm_result
        threat.decision = verdict

        if verdict == self.THREAT:
            action = self._build_action(packet, rules_triggered, severity, llm_result)
            threat.action_taken = action
            self._publish_action(action)
            self._publish_alert(packet, rules_triggered, severity, confidence, llm_result)
            threat.healed_at = timestamp_now()

        if verdict == self.SUSPICIOUS:
            self._publish_alert(packet, rules_triggered, severity, confidence, llm_result)

        self.incident_log.append(threat)

        if self.report_generator and verdict == self.THREAT:
            try:
                self.report_generator.generate_incident_report(threat)
            except Exception as e:
                print(f"[DECISION] Report generation failed: {e}")

        return verdict, threat

    def _build_action(self, packet, rules_triggered, severity, llm_result):
        """Determine the appropriate self-healing action for a confirmed threat."""
        rule_names = [r["rule_name"] for r in rules_triggered]
        actions = []

        if llm_result and "recommended_actions" in llm_result:
            actions = llm_result["recommended_actions"]
        else:
            if "direct_actuator_access" in rule_names:
                actions = ["block_device", "reset_actuator"]
            elif "value_range" in rule_names:
                actions = ["block_device"]
            elif severity >= 9:
                actions = ["network_isolate"]
            else:
                actions = ["block_device"]

        device = self._identify_device(packet)
        actuator = self._identify_actuator(packet)

        primary_action = actions[0] if actions else "block_device"
        duration = 300 if severity < 9 else 600

        return {
            "action": primary_action,
            "device": device,
            "actuator": actuator,
            "duration": duration,
            "all_actions": actions,
            "severity": severity,
            "reason": rules_triggered[0]["detail"] if rules_triggered else "Threat detected",
        }

    def _publish_action(self, action):
        payload = json.dumps(action)
        self.mqtt_client.publish("security/action", payload)
        print(
            f"[DECISION] Published action: {action['action']} "
            f"for device '{action['device']}' ({action['duration']}s)"
        )

    def _publish_alert(self, packet, rules_triggered, severity, confidence, llm_result):
        alert = {
            "severity": severity_label(severity),
            "severity_score": severity,
            "threat_type": rules_triggered[0]["rule_name"] if rules_triggered else "unknown",
            "source_device": packet.client_id,
            "source_ip": packet.source_ip,
            "topic": packet.topic,
            "payload_preview": packet.payload[:100],
            "description": rules_triggered[0]["detail"] if rules_triggered else "",
            "rules_triggered": [r["rule_name"] for r in rules_triggered],
            "confidence": confidence,
            "timestamp": packet.timestamp,
            "llm_analysis": llm_result.get("explanation") if llm_result else None,
        }
        self.mqtt_client.publish("security/alert", json.dumps(alert))
        label = severity_label(severity)
        print(
            f"[DECISION] ALERT [{label}] {alert['threat_type']} "
            f"from {packet.client_id} on {packet.topic}"
        )

    def _identify_device(self, packet):
        """Extract a device identifier from the packet for blocking."""
        cid = packet.client_id
        if cid and cid != "unknown":
            return cid
        return packet.source_ip

    def _identify_actuator(self, packet):
        """If the packet targets an actuator topic, identify which one."""
        topic = packet.topic
        if "/control" in topic:
            parts = topic.split("/")
            if len(parts) >= 2:
                return parts[1]
        return None

    def get_stats(self):
        total = len(self.incident_log)
        threats = sum(1 for t in self.incident_log if t.decision == self.THREAT)
        suspicious = sum(1 for t in self.incident_log if t.decision == self.SUSPICIOUS)
        return {
            "total_incidents": total,
            "threats": threats,
            "suspicious": suspicious,
            "latest": self.incident_log[-1].to_dict() if self.incident_log else None,
        }
