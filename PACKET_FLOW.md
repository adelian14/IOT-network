# How a Packet Flows Through the IoT Security System

This document explains the entire lifecycle of an MQTT message — from the moment it arrives at the IDS node to the final HTML report. It focuses on how the data is shaped at each stage, how it reaches the rule engine, and especially how Gemini receives and processes it.

---

## 1. The Network in One Sentence

Every IoT device (sensors, actuators) talks to a central CPU at `10.0.0.100` using MQTT messages. The IDS node (`10.0.0.99`) silently listens to **every single message** on the network by subscribing to the wildcard topic `#`.

---

## 2. The Big Picture: Pipeline Overview

```
[IoT Device publishes MQTT message]
          |
          v
  [IDSMonitor._on_message()]       <-- Entry point, builds a PacketRecord
          |
          v
      [Firewall]                   <-- Is this sender even allowed?
          |
     PASS / FLAG / BLOCK
          |
          v
     [Rule Engine]                 <-- Is this message suspicious?
          |
    severity + confidence
          |
    If severity >= 5
    AND confidence <= 0.6:
          |
          v
    [Gemini LLM] (async)           <-- "Hey Gemini, what do you think?"
          |
     JSON response
          |
          v
   [Decision Engine]               <-- Final verdict
          |
   SAFE / SUSPICIOUS / THREAT
          |
     If THREAT:
          |-- Publish self-healing action to CPU
          |-- Generate HTML incident report
          `-- Publish alert to security/alert topic
```

---

## 3. Step 1 — A Message Arrives: Building the PacketRecord

When any MQTT message comes in, `IDSMonitor._on_message()` fires. The raw message only contains a **topic** and a **binary payload**. The IDS enriches it into a structured `PacketRecord` object.

### What data engineering happens here?

| Raw MQTT field | Engineering step | Result |
|---|---|---|
| `message.topic` | Used directly | `"home/temp/data"` |
| `message.payload` | Decoded from bytes to string | `"23.5"` |
| (no sender info in MQTT) | Topic is looked up in `mqtt_topics.json` → `network_config.json` to find the device name, then the `client_id` format is constructed (`{name}-sensor`) | `"temp-sensor"` |
| `client_id` | Looked up in `network_config.json` to find the device's IP | `"10.0.0.3"` |
| (none) | Current time is added | `"2026-03-31T14:22:05.123456"` |

**Result — a `PacketRecord` object:**
```python
PacketRecord(
    topic      = "home/temp/data",
    payload    = "23.5",
    client_id  = "temp-sensor",
    source_ip  = "10.0.0.3",
    timestamp  = "2026-03-31T14:22:05.123456"
)
```

This object is what every downstream stage receives. It is also serializable via `.to_dict()` — which is the form passed to Gemini.

The IDS also **keeps a rolling history** of the last 100 messages per `client_id` in `_device_history`. This history is passed to Gemini for context.

---

## 4. Step 2 — The Firewall

The firewall runs four quick checks on the `PacketRecord`:

1. **IP blacklist** — Is `source_ip` in the static block list?
2. **IP whitelist** — Is `source_ip` in the allowed list at all?
3. **Dynamic block** — Was this device temporarily blocked by a previous self-healing action?
4. **Rate limit** — Has this `client_id` sent too many messages in the time window?
5. **Client ID check** — Is this a known device?
6. **Payload size** — Is the payload too large?

**Verdicts:**
- `PASS` — all good, continue
- `FLAG` — something is odd, continue but mark it
- `BLOCK` — hard stop; the packet is dropped and a severity-9 threat is created immediately (skips all further pipeline stages)

If the verdict is `FLAG`, the firewall reasons are **converted into fake rule results** and injected into the rule engine output so they are treated the same way downstream.

---

## 5. Step 3 — The Rule Engine

The rule engine runs six independent checks on the `PacketRecord`. Each check returns a `RuleResult` with a **severity score (0–10)** and a **confidence score (0.0–1.0)**.

| Rule | What it checks | Example trigger |
|---|---|---|
| `value_range` | Is the sensor reading within its expected physical range? | Temperature sensor sends `9999` |
| `topic_acl` | Is the sender authorized to publish on this topic? | A sensor publishes to an actuator control topic |
| `payload_integrity` | Does the payload contain binary data, SQL, XSS, or path traversal? | Payload contains `SELECT * FROM` |
| `direct_actuator_access` | Is a non-CPU device sending commands to an actuator? | `temp-sensor` publishes to `home/thermo/control` |
| `unknown_topic` | Is this a topic that shouldn't exist? | Message on `home/hacked/data` |
| `suspicious_patterns` | Is the payload unusually large or repetitive (flooding)? | 600-character payload or `AAAAAAAAAA` repeated |

### What comes out of the rule engine?

```python
(
    triggered_rules,   # list of dicts, one per triggered rule
    severity,          # highest severity among triggered rules (int 0-10)
    confidence,        # lowest confidence among triggered rules (float 0.0-1.0)
    needs_llm          # True if severity >= 5 AND confidence <= 0.6
)
```

**Example output for a spoofing attack (value out of range):**
```python
triggered_rules = [
    {
        "rule_name": "value_range",
        "triggered": True,
        "severity": 9,
        "confidence": 0.85,
        "detail": "Value 9999.0 outside range [-50, 150] for temp"
    }
]
severity    = 9
confidence  = 0.85
needs_llm   = False   # confidence is > 0.6, so Gemini is NOT called
```

**Example output where Gemini IS called (unknown topic, low confidence):**
```python
triggered_rules = [
    {
        "rule_name": "unknown_topic",
        "triggered": True,
        "severity": 5,
        "confidence": 0.5,
        "detail": "Message on unregistered topic: 'home/mystery/data'"
    }
]
severity    = 5
confidence  = 0.5
needs_llm   = True    # severity >= 5 AND confidence <= 0.6
```

### The escalation condition (when does Gemini get called?)

```
needs_llm = (severity >= 5) AND (confidence <= 0.6)
```

Think of it this way: **the rule engine is confident** when `confidence` is HIGH (close to 1.0). Gemini is only called when the rules are **uncertain** — i.e., when `confidence` is LOW. High-confidence detections (like a sensor sending `9999`) are dealt with directly without Gemini.

---

## 6. Step 4 — Gemini LLM Analysis (the heart of it)

### When is Gemini called?

Only when `needs_llm = True` **and** a Gemini API key is configured. The call is **asynchronous** — it runs in a background thread so it never blocks the main monitoring loop.

### What data is passed to Gemini?

Three things are assembled and sent:

1. **`packet_dict`** — the `.to_dict()` output of the `PacketRecord`
2. **`rules_triggered`** — the list of rule result dicts from the rule engine
3. **`device_history`** — the last 10 messages from this same `client_id` (trimmed from the 100-message rolling buffer)

---

### The Exact Prompt That Goes to Gemini

The prompt is built by `LLMAnalyzer._build_prompt()`. Here is the **template** with every placeholder visible:

```
You are an IoT network security analyst for a smart-home network.

A suspicious MQTT packet has been flagged by the intrusion detection system's rule engine.
Analyze this packet and provide a threat assessment.

## Flagged Packet
- Topic: {packet_dict['topic']}
- Payload: {packet_dict['payload']}
- Source Client ID: {packet_dict['client_id']}
- Source IP: {packet_dict['source_ip']}
- Timestamp: {packet_dict['timestamp']}

## Rules Triggered
  - {rule_name}: {detail} (severity={severity}, confidence={confidence})
  [... one line per triggered rule ...]

[IF device_history exists:]
Recent message history from this device:
  - [{timestamp}] topic={topic} payload={payload}
  [... last 10 messages ...]

## Network Context
This is a smart-home IoT network with:
- 10 sensors (light, temperature, sound, motion, camera, smart-plug, air-purifier, doorbell, smoke/gas, speaker)
- 10 actuators (one per sensor)
- A central CPU/controller at 10.0.0.100 that processes sensor data and sends commands
- Trusted IP range: 10.0.0.1-10.0.0.21 (devices), 10.0.0.99 (IDS), 10.0.0.100 (CPU)
- Communication: MQTT on port 1883

## Required Response Format
Respond ONLY with valid JSON (no markdown fences, no extra text):
{
    "threat_level": "none|low|medium|high|critical",
    "threat_type": "short category name (e.g. spoofing, injection, dos, unauthorized, data_manipulation, reconnaissance, none)",
    "explanation": "detailed explanation of the threat and your reasoning",
    "is_threat": true or false,
    "recommended_actions": ["action1", "action2"],
    "confidence": 0.0 to 1.0
}
```

---

### Full Concrete Example — Injection Attack

**Scenario:** The offensive node (`10.0.0.50`) impersonates a sensor and tries to inject a command directly into an actuator's control topic.

**The packet:**
```
topic     = "home/door/control"
payload   = "OPEN"
client_id = "sound-sensor"         (impersonating a sensor)
source_ip = "10.0.0.50"
timestamp = "2026-03-31T14:35:12.441000"
```

**Rules triggered by the rule engine:**
```python
[
    {
        "rule_name": "direct_actuator_access",
        "severity": 9,
        "confidence": 0.95,
        "detail": "Non-CPU client 'sound-sensor' publishing to actuator topic 'home/door/control'"
    },
    {
        "rule_name": "topic_acl",
        "severity": 8,
        "confidence": 0.9,
        "detail": "Client 'sound-sensor' (device: sound_sensor) not authorized for topic 'home/door/control'. Allowed: ['cpu']"
    }
]
```

> Note: `confidence = 0.9` here, so `needs_llm = False` for this case.
> Below we show a case where Gemini IS called — with a payload integrity violation (lower confidence of 0.6).

**Payload integrity case — Gemini IS called:**

```
topic     = "home/light/data"
payload   = "SELECT * FROM users"
client_id = "light-sensor"
source_ip = "10.0.0.2"
timestamp = "2026-03-31T14:35:12.441000"
```

Rules triggered:
```python
[
    {
        "rule_name": "payload_integrity",
        "severity": 7,
        "confidence": 0.6,
        "detail": "SQL injection pattern in payload: 'SELECT * FROM users'"
    }
]
# severity=7, confidence=0.6 => needs_llm = True (7>=5 AND 0.6<=0.6)
```

**The actual prompt sent to Gemini:**

```
You are an IoT network security analyst for a smart-home network.

A suspicious MQTT packet has been flagged by the intrusion detection system's rule engine.
Analyze this packet and provide a threat assessment.

## Flagged Packet
- Topic: home/light/data
- Payload: SELECT * FROM users
- Source Client ID: light-sensor
- Source IP: 10.0.0.2
- Timestamp: 2026-03-31T14:35:12.441000

## Rules Triggered
  - payload_integrity: SQL injection pattern in payload: 'SELECT * FROM users' (severity=7, confidence=0.6)

Recent message history from this device:
  - [2026-03-31T14:35:10.100000] topic=home/light/data payload=1023
  - [2026-03-31T14:35:10.900000] topic=home/light/data payload=1024
  - [2026-03-31T14:35:11.700000] topic=home/light/data payload=1025
  - [2026-03-31T14:35:12.200000] topic=home/light/data payload=SELECT * FROM users

## Network Context
This is a smart-home IoT network with:
- 10 sensors (light, temperature, sound, motion, camera, smart-plug, air-purifier, doorbell, smoke/gas, speaker)
- 10 actuators (one per sensor)
- A central CPU/controller at 10.0.0.100 that processes sensor data and sends commands
- Trusted IP range: 10.0.0.1-10.0.0.21 (devices), 10.0.0.99 (IDS), 10.0.0.100 (CPU)
- Communication: MQTT on port 1883

## Required Response Format
Respond ONLY with valid JSON (no markdown fences, no extra text):
{
    "threat_level": "none|low|medium|high|critical",
    "threat_type": "short category name (e.g. spoofing, injection, dos, unauthorized, data_manipulation, reconnaissance, none)",
    "explanation": "detailed explanation of the threat and your reasoning",
    "is_threat": true or false,
    "recommended_actions": ["action1", "action2"],
    "confidence": 0.0 to 1.0
}
```

---

### The Exact Output Gemini Returns

Gemini responds with **plain JSON only** (no markdown, no explanation outside the JSON). The IDS strips any accidental markdown fences (` ```json `) before parsing.

**Example Gemini response for the above prompt:**

```json
{
    "threat_level": "high",
    "threat_type": "injection",
    "explanation": "The payload 'SELECT * FROM users' is an SQL injection string, which is completely out of place in a light sensor reading. A legitimate light sensor would publish a numeric lux value (e.g. 1023). The device history confirms that normal payloads for this device are numeric integers around 1023-1025. This payload was almost certainly crafted by an attacker who has compromised the light sensor or is spoofing its client ID to probe the system for SQL injection vulnerabilities. Even though MQTT brokers don't execute SQL, this pattern strongly suggests active reconnaissance or a compromised device acting as a relay for attack payloads.",
    "is_threat": true,
    "recommended_actions": ["block_device", "increase_monitoring"],
    "confidence": 0.92
}
```

After parsing, the IDS appends two extra fields:
```json
{
    "threat_level": "high",
    "threat_type": "injection",
    "explanation": "...",
    "is_threat": true,
    "recommended_actions": ["block_device", "increase_monitoring"],
    "confidence": 0.92,
    "source": "gemini",
    "analyzed_at": "2026-03-31T14:35:13.882000"
}
```

---

### What if Gemini fails or is not configured?

The `_fallback_analysis()` method kicks in and produces the same JSON structure mechanically from the rule results:

```json
{
    "threat_level": "high",
    "threat_type": "payload_integrity",
    "explanation": "Fallback analysis (LLM unavailable). Rules triggered: SQL injection pattern in payload: 'SELECT * FROM users'",
    "is_threat": true,
    "recommended_actions": ["block_device", "increase_monitoring"],
    "confidence": 0.6,
    "source": "fallback",
    "analyzed_at": "2026-03-31T14:35:13.882000"
}
```

---

## 7. Step 5 — The Decision Engine

The decision engine takes everything collected so far and produces a **final verdict**.

### How Gemini's output changes the severity

| Gemini says | Effect on severity |
|---|---|
| `"is_threat": false` | Severity is **reduced by 3** (Gemini cleared it) |
| `"is_threat": true` | Severity is bumped up to at least the Gemini level (`critical`→10, `high`→8, `medium`→6, `low`→3) |

Confidence is also updated: it takes the **maximum** of the rule confidence and Gemini's confidence.

### Verdict thresholds

| Final severity | Verdict |
|---|---|
| >= 7 | **THREAT** |
| 4–6 | **SUSPICIOUS** |
| < 4 | **SAFE** |

### What happens on THREAT?

1. A `ThreatEvent` object is created (the permanent record of the incident)
2. **Self-healing action** is built from `llm_result["recommended_actions"]` (or falls back to rule-based logic) and published to `security/action` as JSON for the CPU to execute
3. An **alert** is published to `security/alert`
4. The threat is appended to the `incident_log`
5. An **HTML incident report** is generated immediately

---

## 8. Step 6 — What Goes Into the Report

The `ReportGenerator.generate_incident_report()` takes the `ThreatEvent` object and renders it into an HTML file saved in `reports_output/`.

### All data fields in the report

**From `ThreatEvent` / `PacketRecord`:**

| Field | Example value |
|---|---|
| Threat ID | `THREAT-20260331143513882000` |
| Timestamp | `2026-03-31 14:35:13.882` |
| Source device (client_id) | `light-sensor` |
| Source IP | `10.0.0.2` |
| MQTT topic | `home/light/data` |
| Payload | `SELECT * FROM users` |
| Severity score | `7` |
| Severity label | `HIGH` |
| Confidence | `0.92` |
| Decision | `THREAT` |

**From the Rule Engine:**

| Field | Example value |
|---|---|
| Rule name | `payload_integrity` |
| Rule detail | `SQL injection pattern in payload: 'SELECT * FROM users'` |
| Rule severity | `7` |
| Rule confidence | `0.6` |

**From Gemini (if called):**

| Field | Example value |
|---|---|
| Threat level | `high` |
| Threat type | `injection` |
| Gemini explanation | *full paragraph text* |
| Is threat | `true` |
| Confidence | `0.92` |
| Source | `gemini` |
| Analyzed at | `2026-03-31T14:35:13.882000` |

**From the Decision Engine:**

| Field | Example value |
|---|---|
| Action taken | `block_device` |
| All actions | `["block_device", "increase_monitoring"]` |
| Target device | `light-sensor` |
| Duration | `300s` |
| Healed at | `2026-03-31T14:35:14.001000` |

**Added by the report generator:**

| Field | Example value |
|---|---|
| Severity color | `#d29922` (yellow for HIGH) |
| Mitigation steps | Bulleted list from `MITIGATION_MAP["block_device"]` |
| Generated at | `2026-03-31 14:35:14` |

### Example mitigation steps for `block_device` action:
- The offending device has been temporarily blocked from the network.
- Investigate the device for compromise or misconfiguration.
- Check firmware version and apply updates if available.
- Review device logs for signs of tampering.

---

## 9. End-to-End Data Flow Summary

```
[light-sensor publishes "SELECT * FROM users" to home/light/data]
                              |
              IDSMonitor._on_message() fires
                              |
              PacketRecord created:
              { topic: "home/light/data",
                payload: "SELECT * FROM users",
                client_id: "light-sensor",
                source_ip: "10.0.0.2",
                timestamp: "2026-03-31T14:35:12.441000" }
                              |
              Firewall: PASS (IP is whitelisted, rate OK)
                              |
              Rule Engine:
                payload_integrity triggered
                severity=7, confidence=0.6
                needs_llm = True
                              |
              Gemini called with full prompt
              (packet + rules + last 10 messages from light-sensor)
                              |
              Gemini returns:
              { threat_level: "high",
                threat_type: "injection",
                is_threat: true,
                confidence: 0.92,
                explanation: "...",
                recommended_actions: ["block_device", "increase_monitoring"] }
                              |
              Decision Engine:
              severity stays at 7 (Gemini confirmed threat)
              confidence bumped to 0.92
              verdict = THREAT (7 >= 7)
                              |
              Self-healing: publish to security/action:
              { action: "block_device",
                device: "light-sensor",
                duration: 300,
                severity: 7 }
                              |
              Alert: publish to security/alert
                              |
              HTML report saved:
              reports_output/incident_20260331_143513_payload_integrity.html
```

---

## 10. Key Design Choices to Note

- **Gemini is non-blocking.** It runs in a background asyncio event loop. The main MQTT listener never waits for it.
- **Gemini is only called for ambiguous cases.** High-confidence detections (like `confidence=0.95` on a direct actuator access) skip Gemini entirely.
- **Gemini can *clear* a threat.** If `is_threat: false` comes back, the severity drops by 3 — potentially moving the verdict from THREAT to SUSPICIOUS or even SAFE.
- **The LLM's recommended_actions are used directly** as the self-healing command to the CPU. Gemini effectively decides what corrective action to take.
- **Device history adds critical context.** The last 10 messages from the device are included in the Gemini prompt so it can spot sudden behavioral changes (e.g., 3 normal readings then a SQL string).
