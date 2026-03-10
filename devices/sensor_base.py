import paho.mqtt.client as mqtt
import time
import random
import argparse
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(SCRIPT_DIR, "..", "config")

SENSOR_SIMULATION = {
    "light": lambda: random.choice(["day", "night"]),
    "temp": lambda: round(random.uniform(18, 35), 1),
    "sound": lambda: random.randint(20, 90),
    "motion": lambda: random.choice(["detected", "none"]),
    "camera": lambda: random.choice(["motion", "clear"]),
    "smart-plug": lambda: random.choice(["on", "off"]),
    "Smart-Air-Purifier": lambda: random.choice(["good", "poor"]),
    "Smart-Doorbell": lambda: random.choice(["pressed", "idle"]),
    "Smoke-Gas-Sensor": lambda: random.choice(["normal", "normal", "normal", "gas_detected"]),
    "Smart-Speaker": lambda: random.choice(["play", "stop"]),
}


def load_config(filename):
    path = os.path.join(CONFIG_DIR, filename)
    with open(path, "r") as f:
        return json.load(f)


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print(f"[{userdata['name']}] Connected to broker at {userdata['broker']}")
    else:
        print(f"[{userdata['name']}] Connection failed with code {rc}")


def main():
    parser = argparse.ArgumentParser(description="IoT Sensor Node")
    parser.add_argument("--device-name", required=True, help="Sensor name (e.g. light, temp, sound)")
    parser.add_argument("--broker", default="10.0.0.100", help="MQTT broker IP")
    parser.add_argument("--interval", type=float, default=5.0, help="Publish interval in seconds")
    args = parser.parse_args()

    mqtt_topics = load_config("mqtt_topics.json")
    topic = mqtt_topics["sensor_topics"].get(args.device_name)
    if not topic:
        print(f"Unknown sensor: {args.device_name}")
        print(f"Available: {list(mqtt_topics['sensor_topics'].keys())}")
        return

    simulator = SENSOR_SIMULATION.get(args.device_name)
    if not simulator:
        print(f"No simulation defined for: {args.device_name}")
        return

    client_id = f"{args.device_name}-sensor"
    userdata = {"name": args.device_name, "broker": args.broker}
    client = mqtt.Client(client_id=client_id, userdata=userdata)
    client.on_connect = on_connect
    client.connect(args.broker, 1883, 60)
    client.loop_start()

    print(f"[{args.device_name}] Sensor started, publishing to {topic} every {args.interval}s")

    try:
        while True:
            value = str(simulator())
            client.publish(topic, value)
            print(f"[{args.device_name}] Published: {value}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n[{args.device_name}] Sensor shutting down.")
    finally:
        client.loop_stop()
        client.disconnect()


if __name__ == "__main__":
    main()
