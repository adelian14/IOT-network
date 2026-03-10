# IoT Network Security & Intrusion Detection System

A complete security system for a GNS3 smart-home IoT network. Includes an MQTT-level firewall/IDS, Gemini LLM-powered threat analysis, automatic self-healing, HTML incident reporting, and an offensive testing node.

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
| Security System (IDS) | 10.0.0.99 | IDS/Firewall |
| CPU / MQTT Broker | 10.0.0.100 | Controller |

## Setup

### 1. Install Dependencies

On each GNS3 node that runs Python scripts:

```bash
pip install -r requirements.txt
```

### 2. Configure Gemini API Key

Copy the example env file and add your API key:

```bash
cp .env.example .env
# Edit .env and set GEMINI_API_KEY
```

If no Gemini API key is provided, the system falls back to rule-based analysis only.

### 3. GNS3 Node Setup

Copy the project files to each GNS3 node. Each node runs a specific script:

**CPU Node (10.0.0.100):**
- Runs the MQTT broker (Mosquitto) and the CPU controller script
- Start Mosquitto: `mosquitto -d`
- Start CPU: `python devices/cpu.py`

**Security System Node (10.0.0.99):**
- Runs the IDS/firewall
- `python -m security.main`

**Sensor Nodes (10.0.0.2 - 10.0.0.11):**
- Each runs the sensor base script with its device name
- Examples:
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

**Actuator Nodes (10.0.0.12 - 10.0.0.21):**
- Each runs the actuator base script with its device name
- Examples:
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

**Offensive Node (10.0.0.50):**
- Interactive mode: `python offensive/attacker.py`
- Automated all attacks: `python offensive/attacker.py auto`
- Scan only: `python offensive/attacker.py scan`
- Specific attack: `python offensive/attacker.py 2` (spoofing)

## Startup Order

1. Start the MQTT broker on the CPU node
2. Start `devices/cpu.py` on the CPU node
3. Start `python -m security.main` on the security node
4. Start sensor scripts on each sensor node
5. Start actuator scripts on each actuator node
6. (When ready to test) Start the offensive node

## Architecture

### Security Pipeline

Every MQTT message flows through this pipeline on the IDS node:

```
Message received (# subscription)
        |
   [Firewall] -- IP whitelist, rate limit, client auth, payload size
        |
   PASS / FLAG / BLOCK
        |
   [Rule Engine] -- value range, topic ACL, payload integrity,
        |            direct actuator access, unknown topics
        |
   Severity + Confidence score
        |
   If severity >= 5 and confidence <= 0.6:
        |-------> [Gemini LLM] (async, non-blocking)
        |                |
        |         analysis result
        |                |
   [Decision Engine] <---+
        |
   SAFE / SUSPICIOUS / THREAT
        |
   If THREAT:
        ├── Publish self-healing action to CPU
        ├── Generate HTML incident report
        └── Log to security/alert topic
```

### Self-Healing Actions

| Action | Effect |
|---|---|
| `block_device` | CPU ignores messages from device for N seconds |
| `reset_actuator` | CPU sends safe default value to actuator |
| `network_isolate` | Extended block + manual review flag |
| `increase_monitoring` | Lower detection thresholds for device |

### Attack Types (Offensive Node)

| # | Attack | Target | IDS Detection |
|---|---|---|---|
| 1 | Network Scan | Subnet | Reconnaissance |
| 2 | Spoofing | Sensor topics | Value range violation |
| 3 | Flooding | All topics | Rate limit exceeded |
| 4 | Injection | Actuator topics | ACL violation, direct actuator access |
| 5 | Replay | Sensor topics | Frequency anomaly |
| 6 | Malformed | Sensor topics | Payload integrity failure |

## Reports

HTML incident reports are saved to `reports_output/`. Each threat generates an individual report and a summary report is generated when the IDS shuts down.

Reports include:
- Threat details (source, topic, payload, severity)
- Timeline with timestamps (detection, analysis, action, healing)
- LLM analysis explanation (if Gemini was consulted)
- Mitigation steps and recommendations

## Configuration

All configuration lives in `config/`:

- `network_config.json` -- Device registry, IP assignments, network topology
- `firewall_rules.json` -- IP whitelist/blacklist, rate limits, payload size limits
- `detection_rules.json` -- Sensor value ranges, topic ACLs, severity thresholds
- `mqtt_topics.json` -- Topic-to-device mapping, security topics

## MQTT Topics

### Sensor Data Topics
`home/{device}/data` -- Sensor readings

### Actuator Control Topics
`home/{device}/control` -- CPU commands to actuators

### Security Topics
- `security/alert` -- IDS threat notifications
- `security/action` -- Self-healing commands to CPU
- `security/heartbeat` -- IDS health check
- `security/cpu_status` -- CPU status reports
- `security/log` -- General IDS event log
