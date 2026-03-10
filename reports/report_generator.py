import os
from datetime import datetime
from collections import Counter

from jinja2 import Environment, FileSystemLoader

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(SCRIPT_DIR, "templates")
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "..", "reports_output")


SEVERITY_COLORS = {
    "CRITICAL": "#da3633",
    "HIGH": "#d29922",
    "MEDIUM": "#e3b341",
    "LOW": "#3fb950",
    "INFO": "#58a6ff",
}

MITIGATION_MAP = {
    "block_device": [
        "The offending device has been temporarily blocked from the network.",
        "Investigate the device for compromise or misconfiguration.",
        "Check firmware version and apply updates if available.",
        "Review device logs for signs of tampering.",
    ],
    "reset_actuator": [
        "The affected actuator has been reset to its safe default state.",
        "Verify the actuator is functioning correctly after reset.",
        "Check for unauthorized physical access to the actuator.",
    ],
    "network_isolate": [
        "The device has been isolated from the network for extended period.",
        "Perform a full security audit on the isolated device.",
        "Do not reconnect until the root cause is identified.",
        "Consider replacing the device if compromise is confirmed.",
    ],
    "increase_monitoring": [
        "Enhanced monitoring has been enabled for this device.",
        "Review subsequent traffic from this device carefully.",
        "Set up additional alerts for repeated anomalies.",
    ],
}


class ReportGenerator:
    def __init__(self, output_dir=None):
        self.output_dir = output_dir or OUTPUT_DIR
        os.makedirs(self.output_dir, exist_ok=True)
        self.env = Environment(
            loader=FileSystemLoader(TEMPLATE_DIR),
            autoescape=True,
        )

    def generate_incident_report(self, threat_event):
        """Generate an HTML incident report for a single threat event."""
        template = self.env.get_template("incident_report.html")

        incident_dict = threat_event.to_dict()
        severity_class = threat_event.severity_label.lower()
        severity_color = SEVERITY_COLORS.get(threat_event.severity_label, "#58a6ff")

        action_name = ""
        if threat_event.action_taken:
            action_name = threat_event.action_taken.get("action", "")

        mitigation_steps = MITIGATION_MAP.get(action_name, [
            "Review the incident details and determine appropriate response.",
            "Monitor the source device for further suspicious activity.",
            "Update detection rules if this is a new attack pattern.",
        ])

        html = template.render(
            incident=incident_dict,
            severity_class=severity_class,
            severity_color=severity_color,
            mitigation_steps=mitigation_steps,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        threat_type = ""
        if threat_event.rules_triggered:
            threat_type = threat_event.rules_triggered[0].get("rule_name", "unknown")
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"incident_{timestamp_str}_{threat_type}.html"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[REPORT] Incident report saved: {filepath}")
        return filepath

    def generate_summary_report(self, incident_log):
        """Generate a summary HTML report from all recorded incidents."""
        if not incident_log:
            print("[REPORT] No incidents to summarize.")
            return None

        template = self.env.get_template("summary_report.html")

        incidents = [t.to_dict() for t in incident_log]

        severity_counts = Counter(t.severity_label for t in incident_log)
        attack_types = Counter()
        for t in incident_log:
            if t.rules_triggered:
                for rule in t.rules_triggered:
                    name = rule.get("rule_name", "unknown") if isinstance(rule, dict) else "unknown"
                    attack_types[name] += 1

        html = template.render(
            date=datetime.now().strftime("%Y-%m-%d"),
            total_incidents=len(incidents),
            critical_count=severity_counts.get("CRITICAL", 0),
            high_count=severity_counts.get("HIGH", 0),
            medium_count=severity_counts.get("MEDIUM", 0),
            low_count=severity_counts.get("LOW", 0) + severity_counts.get("INFO", 0),
            incidents=incidents,
            attack_types=dict(attack_types),
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )

        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"summary_{timestamp_str}.html"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[REPORT] Summary report saved: {filepath}")
        return filepath
