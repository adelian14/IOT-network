"""
IDS Performance Metrics Tracker — standalone MQTT listener.

Subscribes to three channels with strict separation:
  - home/#              : all device traffic (to count total messages)
  - metrics/ground_truth: attack labels published by the offensive node
  - security/alert      : IDS detections (SUSPICIOUS / THREAT verdicts)

The security module is completely blind to metrics/ground_truth — it is
filtered at the entry point of ids_monitor.py before any pipeline stage.
This tracker never imports from security/, ensuring zero data leakage in
either direction.

Usage:
    python -m metrics.tracker
    python -m metrics.tracker --broker 10.0.0.100 --port 1883
"""

import json
import os
import sys
import signal
import argparse
from collections import defaultdict
from datetime import datetime

import paho.mqtt.client as mqtt

# How many seconds either side of a ground-truth event to accept as a match.
# Attack messages and IDS alerts are asynchronous; a 2-second window handles
# normal broker + processing latency without being so wide it produces false
# correlations on busy topics.
CORRELATION_WINDOW_SEC = 2.0

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "reports_output")


# ──────────────────────────────────────────────────────────────────────────────
# Core tracker
# ──────────────────────────────────────────────────────────────────────────────

class MetricsTracker:
    """
    Passively observes MQTT traffic and computes IDS classification metrics.

    Ground truth comes exclusively from metrics/ground_truth (published by the
    offensive node). The tracker never reads from security internals.
    """

    def __init__(self, broker_ip: str = "10.0.0.100", broker_port: int = 1883):
        self.broker_ip = broker_ip
        self.broker_port = broker_port
        self.started_at = datetime.now().isoformat()

        # Raw event lists — appended in _on_message, read at shutdown
        self._all_messages: list[dict] = []    # every home/# message
        self._ground_truth: list[dict] = []    # every metrics/ground_truth event
        self._alerts: list[dict] = []          # every security/alert event

        self._client = mqtt.Client(client_id="metrics-tracker")
        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message

    # ── MQTT callbacks ─────────────────────────────────────────────────────

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            client.subscribe("home/#")
            client.subscribe("metrics/ground_truth")
            client.subscribe("security/alert")
            print(f"[METRICS] Connected to {self.broker_ip}:{self.broker_port}")
            print("[METRICS] Subscribed to: home/#, metrics/ground_truth, security/alert")
            print("[METRICS] Waiting for traffic... (Ctrl+C to stop and generate report)")
        else:
            print(f"[METRICS] Connection failed with code {rc}")

    def _on_message(self, client, userdata, message):
        topic = message.topic
        payload = message.payload.decode(errors="replace")
        now = datetime.now().isoformat()

        if topic == "metrics/ground_truth":
            try:
                event = json.loads(payload)
                event.setdefault("_received_at", now)
                self._ground_truth.append(event)
            except json.JSONDecodeError:
                pass  # malformed ground-truth tag; skip
            return

        if topic == "security/alert":
            try:
                alert = json.loads(payload)
                alert["_received_at"] = now
                self._alerts.append(alert)
            except json.JSONDecodeError:
                pass
            return

        # home/# — count every device message
        self._all_messages.append({
            "topic": topic,
            "payload": payload[:100],
            "timestamp": now,
        })

    # ── Metric computation ─────────────────────────────────────────────────

    @staticmethod
    def _parse_ts(ts_str: str) -> float:
        """Return epoch seconds from an ISO-8601 string, or 0.0 on failure."""
        try:
            return datetime.fromisoformat(ts_str).timestamp()
        except Exception:
            return 0.0

    def compute_metrics(self) -> dict:
        """
        Derive a confusion matrix and classification metrics.

        Unit of analysis: each individual message seen on home/#.

        Ground truth label (positive = attack):
            A message is labelled positive if there exists a ground_truth
            event for the same topic within CORRELATION_WINDOW_SEC seconds.

        Predicted label (positive = detected):
            A message is labelled detected if the IDS fired a security/alert
            for the same topic within CORRELATION_WINDOW_SEC seconds.
        """

        # Build lookup tables: topic -> sorted list of timestamps
        gt_index: dict[str, list[float]] = defaultdict(list)
        for gt in self._ground_truth:
            t = gt.get("target_topic", "")
            ts = self._parse_ts(gt.get("timestamp", gt.get("_received_at", "")))
            gt_index[t].append(ts)

        alert_index: dict[str, list[float]] = defaultdict(list)
        for alert in self._alerts:
            t = alert.get("topic", "")
            # alerts carry packet.timestamp; fall back to when we received it
            ts = self._parse_ts(alert.get("timestamp", alert.get("_received_at", "")))
            alert_index[t].append(ts)

        TP = FP = TN = FN = 0

        for msg in self._all_messages:
            topic = msg["topic"]
            msg_ts = self._parse_ts(msg["timestamp"])
            W = CORRELATION_WINDOW_SEC

            is_attack = any(
                abs(msg_ts - gt_ts) <= W
                for gt_ts in gt_index.get(topic, [])
            )
            is_detected = any(
                abs(msg_ts - alert_ts) <= W
                for alert_ts in alert_index.get(topic, [])
            )

            if is_attack and is_detected:
                TP += 1
            elif is_attack and not is_detected:
                FN += 1
            elif not is_attack and is_detected:
                FP += 1
            else:
                TN += 1

        total = len(self._all_messages)
        precision  = TP / (TP + FP) if (TP + FP) > 0 else 0.0
        recall     = TP / (TP + FN) if (TP + FN) > 0 else 0.0
        f1         = (2 * precision * recall / (precision + recall)
                      if (precision + recall) > 0 else 0.0)
        accuracy   = (TP + TN) / total if total > 0 else 0.0

        # Per-attack-type detection rate
        attack_breakdown: dict[str, dict] = defaultdict(lambda: {"sent": 0, "detected": 0})
        for gt in self._ground_truth:
            at  = gt.get("attack_type", "unknown")
            t   = gt.get("target_topic", "")
            gt_ts = self._parse_ts(gt.get("timestamp", gt.get("_received_at", "")))
            attack_breakdown[at]["sent"] += 1
            if any(abs(gt_ts - a_ts) <= CORRELATION_WINDOW_SEC
                   for a_ts in alert_index.get(t, [])):
                attack_breakdown[at]["detected"] += 1

        return {
            "session": {
                "started_at": self.started_at,
                "ended_at": datetime.now().isoformat(),
                "broker": f"{self.broker_ip}:{self.broker_port}",
                "correlation_window_sec": CORRELATION_WINDOW_SEC,
            },
            "totals": {
                "messages_observed": total,
                "ground_truth_events": len(self._ground_truth),
                "alerts_fired": len(self._alerts),
            },
            "confusion_matrix": {"TP": TP, "FP": FP, "TN": TN, "FN": FN},
            "metrics": {
                "accuracy":  round(accuracy,  4),
                "precision": round(precision, 4),
                "recall":    round(recall,    4),
                "f1_score":  round(f1,        4),
            },
            "attack_breakdown": {
                k: {**v, "detection_rate": round(v["detected"] / v["sent"], 4)
                         if v["sent"] > 0 else 0.0}
                for k, v in attack_breakdown.items()
            },
        }

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def start(self):
        self._client.connect(self.broker_ip, self.broker_port, 60)
        self._client.loop_forever()

    def stop(self):
        self._client.disconnect()


# ──────────────────────────────────────────────────────────────────────────────
# HTML report generation
# ──────────────────────────────────────────────────────────────────────────────

def _pct(v: float) -> str:
    return f"{v * 100:.1f}%"


def _color_metric(v: float) -> str:
    """Return a CSS colour for a 0-1 metric value."""
    if v >= 0.9:
        return "#3fb950"   # green
    if v >= 0.7:
        return "#e3b341"   # amber
    return "#da3633"        # red


def generate_html_report(metrics: dict, output_dir: str = OUTPUT_DIR) -> str:
    """Render the metrics dict to an HTML file and return its path."""
    os.makedirs(output_dir, exist_ok=True)

    s = metrics["session"]
    t = metrics["totals"]
    cm = metrics["confusion_matrix"]
    m = metrics["metrics"]
    ab = metrics["attack_breakdown"]

    TP, FP, TN, FN = cm["TP"], cm["FP"], cm["TN"], cm["FN"]

    # Attack breakdown rows
    breakdown_rows = ""
    for attack_type, stats in sorted(ab.items()):
        dr = stats["detection_rate"]
        dr_color = _color_metric(dr)
        breakdown_rows += f"""
        <tr>
          <td>{attack_type}</td>
          <td>{stats['sent']}</td>
          <td>{stats['detected']}</td>
          <td style="color:{dr_color};font-weight:600">{_pct(dr)}</td>
        </tr>"""

    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"metrics_{timestamp_str}.html"
    filepath = os.path.join(output_dir, filename)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IDS Performance Metrics</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0d1117; color: #c9d1d9; padding: 2rem;
  }}
  h1 {{ color: #58a6ff; font-size: 1.6rem; margin-bottom: 0.25rem; }}
  h2 {{ color: #8b949e; font-size: 0.85rem; font-weight: 400; margin-bottom: 2rem; }}
  h3 {{ color: #58a6ff; font-size: 1rem; margin: 2rem 0 1rem; border-bottom: 1px solid #21262d; padding-bottom: 0.5rem; }}
  .meta {{ color: #8b949e; font-size: 0.8rem; margin-bottom: 2rem; }}
  .meta span {{ margin-right: 2rem; }}

  /* Stat cards */
  .cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .card {{
    background: #161b22; border: 1px solid #21262d; border-radius: 8px;
    padding: 1.25rem 1.5rem; min-width: 160px; flex: 1;
  }}
  .card-label {{ font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }}
  .card-value {{ font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }}

  /* Confusion matrix */
  .cm-wrap {{ display: inline-block; }}
  .cm-table {{ border-collapse: collapse; margin-bottom: 0.5rem; }}
  .cm-table td, .cm-table th {{
    border: 1px solid #21262d; padding: 1rem 1.5rem;
    text-align: center; min-width: 120px;
  }}
  .cm-table th {{ background: #161b22; color: #8b949e; font-size: 0.8rem; }}
  .cm-label {{ font-size: 0.75rem; color: #8b949e; }}
  .tp {{ background: #1a3a1a; color: #3fb950; }}
  .tn {{ background: #1a3a1a; color: #3fb950; }}
  .fp {{ background: #3a1a1a; color: #da3633; }}
  .fn {{ background: #3a2a0a; color: #e3b341; }}
  .cm-cell-label {{ font-size: 0.7rem; color: #8b949e; display: block; }}
  .cm-cell-value {{ font-size: 1.8rem; font-weight: 700; }}

  /* Metrics bar */
  .metrics-grid {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .metric-card {{
    background: #161b22; border: 1px solid #21262d; border-radius: 8px;
    padding: 1rem 1.5rem; min-width: 140px; flex: 1; text-align: center;
  }}
  .metric-name {{ font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.05em; }}
  .metric-value {{ font-size: 2rem; font-weight: 700; margin-top: 0.25rem; }}

  /* Breakdown table */
  table.breakdown {{ width: 100%; border-collapse: collapse; }}
  table.breakdown th, table.breakdown td {{
    border: 1px solid #21262d; padding: 0.6rem 1rem; text-align: left;
  }}
  table.breakdown th {{ background: #161b22; color: #8b949e; font-size: 0.8rem; }}
  table.breakdown tr:nth-child(even) {{ background: #161b22; }}

  footer {{ margin-top: 3rem; color: #8b949e; font-size: 0.75rem; border-top: 1px solid #21262d; padding-top: 1rem; }}
</style>
</head>
<body>

<h1>IDS Performance Metrics Report</h1>
<h2>IoT Network Security System — Offensive Test Evaluation</h2>

<div class="meta">
  <span>Broker: {s['broker']}</span>
  <span>Session start: {s['started_at']}</span>
  <span>Session end: {s['ended_at']}</span>
  <span>Correlation window: ±{s['correlation_window_sec']}s</span>
</div>

<h3>Session Totals</h3>
<div class="cards">
  <div class="card">
    <div class="card-label">Messages Observed</div>
    <div class="card-value" style="color:#58a6ff">{t['messages_observed']}</div>
  </div>
  <div class="card">
    <div class="card-label">Ground Truth Attacks</div>
    <div class="card-value" style="color:#e3b341">{t['ground_truth_events']}</div>
  </div>
  <div class="card">
    <div class="card-label">IDS Alerts Fired</div>
    <div class="card-value" style="color:#da3633">{t['alerts_fired']}</div>
  </div>
</div>

<h3>Confusion Matrix</h3>
<div class="cm-wrap">
  <table class="cm-table">
    <tr>
      <th></th>
      <th>Predicted: Attack</th>
      <th>Predicted: Normal</th>
    </tr>
    <tr>
      <th>Actual: Attack</th>
      <td class="tp">
        <span class="cm-cell-label">True Positive</span>
        <span class="cm-cell-value">{TP}</span>
      </td>
      <td class="fn">
        <span class="cm-cell-label">False Negative</span>
        <span class="cm-cell-value">{FN}</span>
      </td>
    </tr>
    <tr>
      <th>Actual: Normal</th>
      <td class="fp">
        <span class="cm-cell-label">False Positive</span>
        <span class="cm-cell-value">{FP}</span>
      </td>
      <td class="tn">
        <span class="cm-cell-label">True Negative</span>
        <span class="cm-cell-value">{TN}</span>
      </td>
    </tr>
  </table>
</div>

<h3>Classification Metrics</h3>
<div class="metrics-grid">
  <div class="metric-card">
    <div class="metric-name">Accuracy</div>
    <div class="metric-value" style="color:{_color_metric(m['accuracy'])}">{_pct(m['accuracy'])}</div>
  </div>
  <div class="metric-card">
    <div class="metric-name">Precision</div>
    <div class="metric-value" style="color:{_color_metric(m['precision'])}">{_pct(m['precision'])}</div>
  </div>
  <div class="metric-card">
    <div class="metric-name">Recall</div>
    <div class="metric-value" style="color:{_color_metric(m['recall'])}">{_pct(m['recall'])}</div>
  </div>
  <div class="metric-card">
    <div class="metric-name">F1 Score</div>
    <div class="metric-value" style="color:{_color_metric(m['f1_score'])}">{_pct(m['f1_score'])}</div>
  </div>
</div>

<h3>Detection Rate by Attack Type</h3>
<table class="breakdown">
  <thead>
    <tr>
      <th>Attack Type</th>
      <th>Messages Sent</th>
      <th>Detected by IDS</th>
      <th>Detection Rate</th>
    </tr>
  </thead>
  <tbody>
    {breakdown_rows if breakdown_rows else '<tr><td colspan="4" style="color:#8b949e;text-align:center">No attack data recorded</td></tr>'}
  </tbody>
</table>

<footer>
  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} &nbsp;|&nbsp;
  Ground truth source: <code>metrics/ground_truth</code> (offensive node only) &nbsp;|&nbsp;
  IDS output source: <code>security/alert</code>
</footer>

</body>
</html>
"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="IDS metrics tracker")
    parser.add_argument("--broker", default=os.getenv("MQTT_BROKER", "10.0.0.100"))
    parser.add_argument("--port", type=int, default=int(os.getenv("MQTT_PORT", "1883")))
    args = parser.parse_args()

    tracker = MetricsTracker(broker_ip=args.broker, broker_port=args.port)

    def shutdown(sig, frame):
        print("\n[METRICS] Shutting down — computing metrics...")
        tracker.stop()

        results = tracker.compute_metrics()

        cm = results["confusion_matrix"]
        m  = results["metrics"]

        print("\n" + "=" * 50)
        print("  IDS PERFORMANCE RESULTS")
        print("=" * 50)
        print(f"  Messages observed : {results['totals']['messages_observed']}")
        print(f"  Ground truth +ve  : {results['totals']['ground_truth_events']}")
        print(f"  Alerts fired      : {results['totals']['alerts_fired']}")
        print()
        print(f"  Confusion Matrix")
        print(f"    TP={cm['TP']}  FN={cm['FN']}")
        print(f"    FP={cm['FP']}  TN={cm['TN']}")
        print()
        print(f"  Accuracy  : {m['accuracy']:.4f}")
        print(f"  Precision : {m['precision']:.4f}")
        print(f"  Recall    : {m['recall']:.4f}")
        print(f"  F1 Score  : {m['f1_score']:.4f}")
        print()
        print("  Detection by attack type:")
        for at, stats in sorted(results["attack_breakdown"].items()):
            print(f"    {at:20s} {stats['detected']}/{stats['sent']} "
                  f"({stats['detection_rate']*100:.0f}%)")
        print("=" * 50)

        path = generate_html_report(results)
        print(f"\n[METRICS] Report saved: {path}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    try:
        tracker.start()
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
