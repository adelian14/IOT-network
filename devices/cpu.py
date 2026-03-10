import paho.mqtt.client as mqtt
import time
import threading
import json
from datetime import datetime, timedelta

BROKER = "10.0.0.100"

SENSOR_TOPICS = {
    "light": "home/lighting/data",
    "temp": "home/thermo/data",
    "sound": "home/sound/data",
    "motion": "home/door/data",
    "camera": "home/camera/data",
    "smart-plug": "home/smart-plug/data",
    "Smart-Air-Purifier": "home/Smart-Air-Purifier/data",
    "Smart-Doorbell": "home/Smart-Doorbell/data",
    "Smoke-Gas-Sensor": "home/Smoke-Gas-Sensor/data",
    "Smart-Speaker": "home/Smart-Speaker/data",
}

ACTUATOR_TOPICS = {
    "light": "home/lighting/control",
    "thermo": "home/thermo/control",
    "sound": "home/sound/control",
    "door": "home/door/control",
    "camera": "home/camera/control",
    "smart-plug": "home/smart-plug/control",
    "Smart-Air-Purifier": "home/Smart-Air-Purifier/control",
    "Smart-Doorbell": "home/Smart-Doorbell/control",
    "Smoke-Gas-Sensor": "home/Smoke-Gas-Sensor/control",
    "Smart-Speaker": "home/Smart-Speaker/control",
}

SECURITY_TOPICS = {
    "alert": "security/alert",
    "action": "security/action",
    "cpu_status": "security/cpu_status",
}

ACTUATOR_SAFE_DEFAULTS = {
    "light": "day",
    "thermo": "off",
    "sound": "unmute",
    "door": "lock",
    "camera": "off",
    "smart-plug": "off",
    "Smart-Air-Purifier": "stop",
    "Smart-Doorbell": "idle",
    "Smoke-Gas-Sensor": "normal",
    "Smart-Speaker": "stop",
}

sensor_data = {}
blocked_devices = {}
security_log = []


def is_device_blocked(device_key):
    """Check if a device is currently blocked; auto-remove expired blocks."""
    if device_key in blocked_devices:
        if datetime.now() < blocked_devices[device_key]:
            return True
        else:
            del blocked_devices[device_key]
            log_security_event(f"Auto-unblocked device: {device_key}")
    return False


def log_security_event(message):
    entry = f"[{datetime.now().isoformat()}] {message}"
    security_log.append(entry)
    print(f"[SECURITY] {entry}")


def handle_security_action(payload_str):
    """Process self-healing commands from the IDS."""
    try:
        action = json.loads(payload_str)
    except json.JSONDecodeError:
        log_security_event(f"Malformed security action: {payload_str}")
        return

    action_type = action.get("action")
    device = action.get("device")
    duration = action.get("duration", 300)

    if action_type == "block_device":
        unblock_time = datetime.now() + timedelta(seconds=duration)
        blocked_devices[device] = unblock_time
        log_security_event(f"Blocked device '{device}' for {duration}s")

    elif action_type == "reset_actuator":
        actuator_key = action.get("actuator", device)
        safe_value = ACTUATOR_SAFE_DEFAULTS.get(actuator_key, "off")
        topic = ACTUATOR_TOPICS.get(actuator_key)
        if topic:
            client.publish(topic, safe_value)
            log_security_event(f"Reset actuator '{actuator_key}' to safe default: {safe_value}")

    elif action_type == "unblock_device":
        if device in blocked_devices:
            del blocked_devices[device]
            log_security_event(f"Manually unblocked device: {device}")

    elif action_type == "increase_monitoring":
        log_security_event(f"Increased monitoring for device: {device}")

    elif action_type == "network_isolate":
        unblock_time = datetime.now() + timedelta(seconds=duration * 2)
        blocked_devices[device] = unblock_time
        log_security_event(f"Isolated device '{device}' for {duration * 2}s (network isolate)")

    else:
        log_security_event(f"Unknown security action: {action_type}")


def handle_security_alert(payload_str):
    """Log incoming threat alerts from IDS."""
    try:
        alert = json.loads(payload_str)
        severity = alert.get("severity", "unknown")
        threat_type = alert.get("threat_type", "unknown")
        source = alert.get("source_device", "unknown")
        log_security_event(
            f"ALERT [{severity.upper()}] type={threat_type} source={source} - {alert.get('description', '')}"
        )
    except json.JSONDecodeError:
        log_security_event(f"Received alert: {payload_str}")


def process_data():
    global sensor_data
    actions = []

    light_condition = sensor_data.get("light")
    if light_condition and not is_device_blocked("light"):
        if light_condition == "day":
            client.publish(ACTUATOR_TOPICS["light"], "day")
            actions.append("Lighting: day mode")
        elif light_condition == "night":
            client.publish(ACTUATOR_TOPICS["light"], "night")
            actions.append("Lighting: night mode")

    if not is_device_blocked("temp"):
        try:
            temp = float(sensor_data.get("temp", 25))
            if temp > 28:
                client.publish(ACTUATOR_TOPICS["thermo"], "cool")
                actions.append("Thermo: cooling ON")
            elif temp < 22:
                client.publish(ACTUATOR_TOPICS["thermo"], "heat")
                actions.append("Thermo: heating ON")
            else:
                client.publish(ACTUATOR_TOPICS["thermo"], "off")
                actions.append("Thermo: OFF")
        except (ValueError, TypeError):
            actions.append("Thermo: invalid data, skipping")

    if not is_device_blocked("sound"):
        try:
            sound = int(sensor_data.get("sound", 0))
            if sound > 80:
                client.publish(ACTUATOR_TOPICS["sound"], "mute")
                actions.append("Sound: MUTE")
            elif sound < 50:
                client.publish(ACTUATOR_TOPICS["sound"], "unmute")
                actions.append("Sound: UNMUTE")
        except (ValueError, TypeError):
            actions.append("Sound: invalid data, skipping")

    if not is_device_blocked("motion"):
        motion = sensor_data.get("motion")
        if motion == "detected":
            client.publish(ACTUATOR_TOPICS["door"], "unlock")
            actions.append("Door: UNLOCKED (movement)")
        else:
            client.publish(ACTUATOR_TOPICS["door"], "lock")
            actions.append("Door: LOCKED (no movement)")

    if not is_device_blocked("camera"):
        camera = sensor_data.get("camera")
        if camera == "motion":
            client.publish(ACTUATOR_TOPICS["camera"], "on")
            actions.append("Camera: ON (motion detected)")
        else:
            client.publish(ACTUATOR_TOPICS["camera"], "off")
            actions.append("Camera: OFF (no motion)")

    if not is_device_blocked("smart-plug"):
        plug_status = sensor_data.get("smart-plug")
        if plug_status == "on":
            client.publish(ACTUATOR_TOPICS["smart-plug"], "on")
            actions.append("Smart Plug: ON")
        elif plug_status == "off":
            client.publish(ACTUATOR_TOPICS["smart-plug"], "off")
            actions.append("Smart Plug: OFF")

    if not is_device_blocked("Smart-Air-Purifier"):
        air_quality = sensor_data.get("Smart-Air-Purifier", "good")
        if air_quality == "poor":
            client.publish(ACTUATOR_TOPICS["Smart-Air-Purifier"], "start")
            actions.append("Air Purifier: ON (poor air quality)")
        else:
            client.publish(ACTUATOR_TOPICS["Smart-Air-Purifier"], "stop")
            actions.append("Air Purifier: OFF (good air quality)")

    if not is_device_blocked("Smart-Doorbell"):
        doorbell_status = sensor_data.get("Smart-Doorbell")
        if doorbell_status == "pressed":
            client.publish(ACTUATOR_TOPICS["Smart-Doorbell"], "ring")
            actions.append("Doorbell: Ringing")

    if not is_device_blocked("Smoke-Gas-Sensor"):
        gas_status = sensor_data.get("Smoke-Gas-Sensor")
        if gas_status == "gas_detected":
            client.publish(ACTUATOR_TOPICS["Smoke-Gas-Sensor"], "alert")
            actions.append("Gas Sensor: GAS DETECTED - ALERT!")
        else:
            client.publish(ACTUATOR_TOPICS["Smoke-Gas-Sensor"], "normal")
            actions.append("Gas Sensor: Normal")

    if not is_device_blocked("Smart-Speaker"):
        speaker_cmd = sensor_data.get("Smart-Speaker")
        if speaker_cmd == "play":
            client.publish(ACTUATOR_TOPICS["Smart-Speaker"], "play")
            actions.append("Smart Speaker: Playing music")
        elif speaker_cmd == "stop":
            client.publish(ACTUATOR_TOPICS["Smart-Speaker"], "stop")
            actions.append("Smart Speaker: Stopped")

    if actions:
        print("\n".join(actions))
    print("-" * 40)


def send_data_periodically():
    process_data()
    threading.Timer(5, send_data_periodically).start()


def send_heartbeat():
    """Periodically publish CPU status so IDS knows we're alive."""
    status = {
        "status": "online",
        "timestamp": datetime.now().isoformat(),
        "blocked_devices": list(blocked_devices.keys()),
        "active_sensors": list(sensor_data.keys()),
    }
    client.publish(SECURITY_TOPICS["cpu_status"], json.dumps(status))
    threading.Timer(10, send_heartbeat).start()


def on_message(client, userdata, message):
    global sensor_data
    topic = message.topic
    payload = message.payload.decode()

    if topic == SECURITY_TOPICS["alert"]:
        handle_security_alert(payload)
        return

    if topic == SECURITY_TOPICS["action"]:
        handle_security_action(payload)
        return

    for key, sensor_topic in SENSOR_TOPICS.items():
        if topic == sensor_topic:
            if is_device_blocked(key):
                print(f"[BLOCKED] Ignoring data from blocked device: {key}")
                return
            sensor_data[key] = payload
            print(f"[Received] {key}: {payload}")
            return


client = mqtt.Client(client_id="cpu-controller")
client.on_message = on_message
client.connect(BROKER, 1883, 60)

for topic in SENSOR_TOPICS.values():
    client.subscribe(topic)

client.subscribe(SECURITY_TOPICS["alert"])
client.subscribe(SECURITY_TOPICS["action"])

print("CPU is running with security integration...")
send_data_periodically()
send_heartbeat()
client.loop_forever()
