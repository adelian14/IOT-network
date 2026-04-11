# IoT Network Security & Intrusion Detection System

A complete red-team / blue-team security simulation for a GNS3 smart-home IoT network. The system combines an MQTT-level firewall, a multi-stage intrusion detection pipeline, Gemini LLM-powered threat analysis, automatic self-healing, and a ground-truth-based performance evaluation framework.

---

## Table of Contents

1. [Network Topology](#network-topology)
2. [Architecture Overview](#architecture-overview)
3. [Security System (IDS)](#security-system-ids)
   - [Firewall](#1-firewall)
   - [Rule Engine](#2-rule-engine)
   - [LLM Analyzer](#3-llm-analyzer-gemini)
   - [Decision Engine & Self-Healing](#4-decision-engine--self-healing)
4. [Offensive Node](#offensive-node)
   - [Attack Types](#attack-types)
   - [Ground Truth Tagging](#ground-truth-tagging)
5. [Performance Metrics](#performance-metrics)
6. [Reports & Dashboard](#reports--dashboard)
7. [Configuration](#configuration)
8. [MQTT Topics](#mqtt-topics)
9. [Setup & Installation](#setup--installation)
10. [Startup Order](#startup-order)
11. [Reference Documentation](#reference-documentation)

---

## Network Topology

| Device | IP | Role |
|---|---|---|
| Router | 10.0.0.1 | Gateway |
| Light Sensor | 10.0.0.2 | Sensor |
| Temp Sensor | 10.0.0.3 | Sensor |
| Sound Sensor | 10.0.0.4 | Sensor |
| Motion Sensor | 10.0.0.5 | Sensor |
| Camera Sensor | 10.0.0.6 | Sensor |
| Smart Plug Sensor | 10.0.0.7 | Sensor |
| Air Purifier Sensor | 10.0.0.8 | Sensor |
| Doorbell Sensor | 10.0.0.9 | Sensor |
| Smoke/Gas Sensor | 10.0.0.10 | Sensor |
| Smart Speaker Sensor | 10.0.0.11 | Sensor |
| Light Actuator | 10.0.0.12 | Actuator |
| Thermo Actuator | 10.0.0.13 | Actuator |
| Sound Actuator | 10.0.0.14 | Actuator |
| Door Actuator | 10.0.0.15 | Actuator |
| Camera Actuator | 10.0.0.16 | Actuator |
| Smart Plug Actuator | 10.0.0.17 | Actuator |
| Air Purifier Actuator | 10.0.0.18 | Actuator |
| Doorbell Actuator | 10.0.0.19 | Actuator |
| Smoke/Gas Actuator | 10.0.0.20 | Actuator |
| Smart Speaker Actuator | 10.0.0.21 | Actuator |
| Offensive Node | 10.0.0.50 | Attacker |
| Security System (IDS) | 10.0.0.99 | IDS / Firewall |
| CPU / MQTT Broker | 10.0.0.100 | Controller |

---

## Architecture Overview

The system has three independent layers that communicate only through MQTT:

```
┌─────────────────────────────────────────────────────────────┐
│  Sensors (10.0.0.2–11)                                      │
│  Publish: home/{device}/data                                │
└────────────────────┬────────────────────────────────────────┘
                     │ MQTT Broker (10.0.0.100)
          ┌──────────┴──────────┐
          │                     │
   ┌──────▼──────┐       ┌──────▼──────────────────┐
   │  CPU Node   │       │  IDS Node (10.0.0.99)   │
   │  cpu.py     │       │  Subscribes to ALL (#)   │
   │             │◄──────│  security/action         │
   │  Reads data │       │  Runs full pipeline      │
   │  Commands   │       │  Publishes alerts        │
   │  actuators  │       └─────────────────────────-┘
   └──────┬──────┘
          │ home/{device}/control
   ┌──────▼──────────────────┐
   │  Actuators (10.0.0.12–21)│
   └──────────────────────────┘
```

The **CPU** is the brain: it reads all sensor data and commands actuators every 5 seconds. The **IDS** is a silent observer that subscribes to every topic and acts on anything suspicious — it never interferes with normal traffic, only publishes back on `security/` topics. The **Offensive Node** (10.0.0.50) attacks the network; the **Metrics Tracker** watches all three channels to measure IDS performance objectively.

---

## Security System (IDS)

Run with: `python -m security.main`

Every MQTT message received by the IDS passes through a four-stage pipeline:

```
Message arrives (# subscription)
         │
         ├── topic starts with "security/" or "metrics/" → DISCARD (not processed)
         │
    [1. Firewall]
         │  - IP whitelist / static blacklist check
         │  - Dynamic block check (devices blocked by prior threats)
         │  - Per-device rate limit (sliding window)
         │  - Client ID authentication (known device registry)
         │  - Payload size limit
         │
    PASS / FLAG / BLOCK
         │
         ├── BLOCK → _handle_block() → Decision Engine (severity 9) → THREAT
         │
    [2. Rule Engine]
         │  - value_range     : sensor reading outside expected bounds
         │  - topic_acl       : client publishing to a topic it doesn't own
         │  - payload_integrity: binary chars, SQL/XSS patterns, path traversal
         │  - direct_actuator_access: non-CPU client writing to a /control topic
         │  - unknown_topic   : topic not in registered device registry
         │  - suspicious_pattern: oversized payload, repeated-character flood data
         │
    severity (0–10) + confidence (0.0–1.0)
         │
         ├── No rules triggered AND firewall PASS → silent drop (SAFE)
         │
    [3. LLM Analyzer]  ← only when severity ≥ 5 AND confidence ≤ 0.6
         │  Runs asynchronously in a background thread (never blocks the pipeline)
         │  Sends packet context + rule results + device history to Gemini
         │  Returns: threat_level, threat_type, explanation, recommended_actions
         │  Falls back to rule-based logic if no API key is configured
         │
    [4. Decision Engine]
         │  Combines rule severity with LLM result:
         │    - LLM says not a threat → severity -= 3
         │    - LLM says is a threat  → severity = max(rule, llm)
         │
         ├── severity ≥ 7 → THREAT
         ├── severity ≥ 4 → SUSPICIOUS
         └── severity < 4 → SAFE
```

### 1. Firewall

`security/firewall.py`

| Check | Verdict on failure |
|---|---|
| IP in static blacklist | BLOCK |
| IP under dynamic block | BLOCK |
| Rate limit exceeded | FLAG |
| Unknown client ID | FLAG |
| Payload too large | FLAG |

Rate limits are configured per device type (`sensor`, `actuator`, `cpu`, `default`) with a sliding-window counter. Dynamic blocks are added by the Decision Engine when a threat is confirmed and expire after a configurable duration.

### 2. Rule Engine

`security/rule_engine.py`

| Rule | Severity | Detects |
|---|---|---|
| `value_range` | 7–9 | Spoofed sensor readings outside physical bounds |
| `topic_acl` | 8 | Client publishing to a topic it has no right to write |
| `payload_integrity` | 4–7 | Malformed data, SQL injection, XSS, path traversal, binary content |
| `direct_actuator_access` | 9 | Any non-CPU node writing to a `/control` topic |
| `unknown_topic` | 5 | Traffic on a topic not registered in the device registry |
| `suspicious_pattern` | 5–6 | Oversized payload, repeated-character flood payloads |

### 3. LLM Analyzer (Gemini)

`security/llm_analyzer.py`

The LLM stage is only invoked when the rule engine is uncertain (high severity but low confidence). It receives:

- The flagged packet (topic, payload, client ID, source IP, timestamp)
- All triggered rule results with their severity and detail
- The last 10 messages from the same device (historical context)

Gemini is asked to return structured JSON:
```json
{
    "threat_level": "none|low|medium|high|critical",
    "threat_type": "spoofing|injection|dos|...",
    "explanation": "...",
    "is_threat": true,
    "recommended_actions": ["block_device", "reset_actuator"],
    "confidence": 0.85
}
```

The LLM's `recommended_actions` override the default action logic in the Decision Engine when present. If no Gemini API key is set, the system falls back to a rule-based severity mapping with no external calls.

### 4. Decision Engine & Self-Healing

`security/decision_engine.py`

On a **THREAT** verdict the Decision Engine:
1. Publishes a self-healing action to `security/action` (consumed by the CPU)
2. Publishes a threat alert to `security/alert`
3. Generates an HTML incident report in `reports_output/`
4. Appends the event to the in-memory `incident_log` (used for the summary report at shutdown)

| Self-Healing Action | Effect on CPU |
|---|---|
| `block_device` | CPU ignores all data from that device for N seconds |
| `reset_actuator` | CPU sends the safe default value to the affected actuator |
| `network_isolate` | Extended block (2× duration) + manual review flag |
| `increase_monitoring` | CPU logs enhanced status; IDS lowers its thresholds |

The CPU (`devices/cpu.py`) maintains its own `blocked_devices` dict. When a device is blocked, every call to `process_data()` skips it via `is_device_blocked()`. Blocks expire automatically after their duration has elapsed.

---

## Offensive Node

Run with: `python offensive/attacker.py [auto|scan|1-6]`

```
python offensive/attacker.py          # interactive menu
python offensive/attacker.py auto     # run all attacks in sequence
python offensive/attacker.py scan     # network recon only
python offensive/attacker.py 2        # specific attack (spoofing)
```

### Attack Types

| # | Attack | MQTT Client ID | Target | Primary IDS Detection |
|---|---|---|---|---|
| 1 | Network Scan | — (TCP sockets) | Subnet 10.0.0.x | Network-level recon (not MQTT) |
| 2 | Spoofing | `spoofed-sensor` | `home/*/data` | `value_range` violation |
| 3 | Flooding | `flood-bot` | `home/*/data` + random topics | Firewall rate limit |
| 4 | Injection | `injector-node` | `home/*/control` | `direct_actuator_access` (severity 9) |
| 5 | Replay | `replay-attacker` | `home/*/data` | `suspicious_pattern`, rate limit |
| 6 | Malformed | `malform-bot` | `home/*/data` | `payload_integrity` violation |

Each attack module connects with a fake MQTT client ID that is not in the network's device registry, which triggers `topic_acl` and `unknown client` checks in addition to the primary detection rule.

### Ground Truth Tagging

`offensive/ground_truth.py`

Every time an attack module publishes a malicious message, it simultaneously publishes a structured label to `metrics/ground_truth`:

```json
{
    "attack_type": "spoofing",
    "target_topic": "home/thermo/data",
    "payload": "999",
    "timestamp": "2026-04-05T12:00:01.123"
}
```

**No-leakage guarantee**: The IDS filters out `metrics/` topics at the very first line of `_on_message` in `ids_monitor.py`, before the Firewall, Rule Engine, LLM, or Decision Engine are ever invoked. The `metrics/` module never imports from `security/`. There is zero coupling in either direction.

The network scan (`scanner.py`) operates at the TCP socket level and produces no MQTT messages, so it is not tagged.

The replay attack tags only the **replay phase** — the capture phase is passive sniffing of legitimate traffic and is intentionally not labelled as an attack.

---

## Performance Metrics

`metrics/tracker.py`

A fully independent MQTT client that measures IDS classification performance by observing three channels simultaneously:

| Subscription | Purpose |
|---|---|
| `home/#` | Counts all device traffic (total message population) |
| `metrics/ground_truth` | Receives attack labels from the offensive node |
| `security/alert` | Receives IDS detections (SUSPICIOUS / THREAT verdicts) |

Run independently on any node that can reach the broker:

```bash
python -m metrics.tracker
python -m metrics.tracker --broker 10.0.0.100 --port 1883
```

Press `Ctrl+C` to stop. The tracker correlates ground truth events with IDS alerts using a ±2-second time window per topic, then computes:

### Classification Mapping

| Ground Truth | IDS Verdict | Result |
|---|---|---|
| Attack message | Alert fired | **TP** — correctly detected |
| Legitimate message | No alert | **TN** — correctly ignored |
| Legitimate message | Alert fired | **FP** — false alarm |
| Attack message | No alert | **FN** — missed detection |

### Output Metrics

- **Accuracy** — (TP + TN) / total messages
- **Precision** — TP / (TP + FP) — how reliable the alerts are
- **Recall** — TP / (TP + FN) — how many attacks were caught
- **F1 Score** — harmonic mean of precision and recall
- **Confusion Matrix** — raw TP / FP / TN / FN counts
- **Detection rate per attack type** — e.g. spoofing 18/20 (90%)

Results are printed to stdout and saved as an HTML report to `reports_output/metrics_<timestamp>.html`.

---

## Reports & Dashboard

### Report Types

| File Pattern | Generated By | Content |
|---|---|---|
| `incident_YYYYMMDD_HHMMSS_<type>.html` | Decision Engine (per threat) | Threat details, timeline, LLM explanation, mitigation steps |
| `summary_YYYYMMDD_HHMMSS.html` | IDS on shutdown | All incidents, severity breakdown, attack type counts |
| `metrics_YYYYMMDD_HHMMSS.html` | Metrics tracker on shutdown | Confusion matrix, accuracy/precision/recall/F1, per-attack detection rates |

All reports are written to `reports_output/`.

### Dashboard

Open `dashboard.html` in a browser (requires a local HTTP server to load the manifest):

```bash
python -m http.server 8080
# then open http://localhost:8080/dashboard.html
```

The dashboard reads `reports_output/reports_manifest.json` and renders cards for all three report types with distinct visual styling:

- **Red** — incident reports
- **Blue** — session summaries
- **Green** — performance metrics

### Regenerating the Manifest

After a test session, regenerate the manifest to include new reports:

```bash
python generate_reports_manifest.py
```

This picks up all `incident_*`, `summary_*`, and `metrics_*` HTML files and writes `reports_output/reports_manifest.json`. The dashboard's Refresh button re-fetches the manifest without a page reload.

---

## Configuration

All configuration lives in `config/`:

| File | Contents |
|---|---|
| `network_config.json` | Device registry — name, IP, type, MQTT client ID for every node |
| `firewall_rules.json` | IP whitelist/blacklist, per-type rate limits, payload size limit, dynamic block duration |
| `detection_rules.json` | Per-sensor value ranges, topic ACLs, severity thresholds, LLM escalation threshold |
| `mqtt_topics.json` | Topic-to-device map, full lists of sensor/actuator/security topics |

The IDS, Firewall, and Rule Engine all load these at startup. No code changes are needed to add a new device or adjust thresholds.

---

## MQTT Topics

### Normal Traffic

| Pattern | Publisher | Subscriber(s) |
|---|---|---|
| `home/{device}/data` | Sensor node | CPU, IDS |
| `home/{device}/control` | CPU only | Actuator node, IDS |
| `home/{device}/ack` | Actuator (acknowledgement) | CPU |

### Security Channel

| Topic | Publisher | Subscriber(s) | Purpose |
|---|---|---|---|
| `security/alert` | IDS | CPU, any monitor | Threat notification |
| `security/action` | IDS | CPU | Self-healing command |
| `security/heartbeat` | IDS | — | IDS health check |
| `security/cpu_status` | CPU | IDS | CPU heartbeat with block list |
| `security/log` | IDS | — | General IDS event log |

### Metrics Channel (IDS-invisible)

| Topic | Publisher | Subscriber(s) | Purpose |
|---|---|---|---|
| `metrics/ground_truth` | Offensive node | Metrics tracker only | Attack labels for evaluation |

---

## Setup & Installation

### 1. Install Dependencies

On each GNS3 node that runs Python scripts:

```bash
pip install -r requirements.txt
```

### 2. Configure Gemini API Key (optional)

```bash
cp .env.example .env
# edit .env and set GEMINI_API_KEY
```

If no key is provided the system falls back to rule-based analysis automatically. No other changes are required.

### 3. Node Scripts

**CPU Node (10.0.0.100)**
```bash
mosquitto -d                  # start MQTT broker
python devices/cpu.py
```

**Security / IDS Node (10.0.0.99)**
```bash
python -m security.main
```

**Sensor Nodes (10.0.0.2–10.0.0.11)**
```bash
python devices/sensor_base.py --device-name light
python devices/sensor_base.py --device-name temp
python devices/sensor_base.py --device-name sound
python devices/sensor_base.py --device-name motion
python devices/sensor_base.py --device-name camera
python devices/sensor_base.py --device-name smart-plug
python devices/sensor_base.py --device-name Smart-Air-Purifier
python devices/sensor_base.py --device-name Smart-Doorbell
python devices/sensor_base.py --device-name Smoke-Gas-Sensor
python devices/sensor_base.py --device-name Smart-Speaker
```

**Actuator Nodes (10.0.0.12–10.0.0.21)**
```bash
python devices/actuator_base.py --device-name light
python devices/actuator_base.py --device-name thermo
python devices/actuator_base.py --device-name sound
python devices/actuator_base.py --device-name door
python devices/actuator_base.py --device-name camera
python devices/actuator_base.py --device-name smart-plug
python devices/actuator_base.py --device-name Smart-Air-Purifier
python devices/actuator_base.py --device-name Smart-Doorbell
python devices/actuator_base.py --device-name Smoke-Gas-Sensor
python devices/actuator_base.py --device-name Smart-Speaker
```

**Offensive Node (10.0.0.50)**
```bash
python offensive/attacker.py          # interactive menu
python offensive/attacker.py auto     # all attacks in sequence
python offensive/attacker.py scan     # network recon only
python offensive/attacker.py 2        # single attack by number
```

**Metrics Tracker (any node)**
```bash
python -m metrics.tracker
# runs until Ctrl+C, then prints results and saves HTML report
```

---

## Startup Order

1. Start Mosquitto on the CPU node
2. Start `devices/cpu.py` on the CPU node
3. Start `python -m security.main` on the IDS node
4. Start `python -m metrics.tracker` on the metrics node (or any node)
5. Start sensor scripts on each sensor node
6. Start actuator scripts on each actuator node
7. Start `python offensive/attacker.py` when ready to test

Stop order: `Ctrl+C` on the IDS (generates summary report), then `Ctrl+C` on the metrics tracker (generates metrics report), then run `python generate_reports_manifest.py` to update the dashboard.

---

## Reference Documentation

- **Security Module — Packet Flow**  
  https://adelian14.github.io/IOT-network/PACKET_FLOW.html  

- **Security Module — Gemini Component**  
  https://adelian14.github.io/IOT-network/GEMINI_ROLE.html  

- **Offensive Module — Attack Simulation**  
  https://adelian14.github.io/IOT-network/offensive_module.html  

- **System — Metrics & Evaluation**  
  https://adelian14.github.io/IOT-network/metrics_explained.html  
