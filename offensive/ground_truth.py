"""
Ground truth publisher for the offensive node.

Every time an attack module publishes a malicious message, it calls tag()
to also publish a structured label to metrics/ground_truth. This topic is
explicitly ignored by the IDS (filtered before any pipeline stage), so the
security module cannot use it to cheat.

The metrics tracker subscribes to metrics/ground_truth independently and
uses it to compute TP/FP/TN/FN after the test run.
"""

import json
from datetime import datetime

GROUND_TRUTH_TOPIC = "metrics/ground_truth"


def tag(client, attack_type: str, topic: str, payload: str) -> None:
    """
    Publish a ground truth label alongside an attack message.

    Args:
        client:      The paho MQTT client that just published the attack.
        attack_type: Short label for the attack (e.g. "spoofing", "flooding").
        topic:       The MQTT topic the attack was published to.
        payload:     The attack payload (truncated to 200 chars for safety).
    """
    event = {
        "attack_type": attack_type,
        "target_topic": topic,
        "payload": str(payload)[:200],
        "timestamp": datetime.now().isoformat(),
    }
    client.publish(GROUND_TRUTH_TOPIC, json.dumps(event))
