import paho.mqtt.client as mqtt
import argparse
import json
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_DIR = os.path.join(SCRIPT_DIR, "..", "config")


def load_config(filename):
    path = os.path.join(CONFIG_DIR, filename)
    with open(path, "r") as f:
        return json.load(f)


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        topic = userdata["topic"]
        client.subscribe(topic)
        print(f"[{userdata['name']}] Connected and subscribed to {topic}")
    else:
        print(f"[{userdata['name']}] Connection failed with code {rc}")


def on_message(client, userdata, message):
    command = message.payload.decode()
    name = userdata["name"]
    print(f"[{name}] Received command: {command} on {message.topic}")

    ack_topic = f"home/{name}/ack"
    client.publish(ack_topic, f"ACK:{command}")


def main():
    parser = argparse.ArgumentParser(description="IoT Actuator Node")
    parser.add_argument("--device-name", required=True, help="Actuator name (e.g. light, thermo, door)")
    parser.add_argument("--broker", default="10.0.0.100", help="MQTT broker IP")
    args = parser.parse_args()

    mqtt_topics = load_config("mqtt_topics.json")
    topic = mqtt_topics["actuator_topics"].get(args.device_name)
    if not topic:
        print(f"Unknown actuator: {args.device_name}")
        print(f"Available: {list(mqtt_topics['actuator_topics'].keys())}")
        return

    client_id = f"{args.device_name}-actuator"
    userdata = {"name": args.device_name, "topic": topic, "broker": args.broker}
    client = mqtt.Client(client_id=client_id, userdata=userdata)
    client.on_connect = on_connect
    client.on_message = on_message
    client.user_data_set(userdata)
    client.connect(args.broker, 1883, 60)

    print(f"[{args.device_name}] Actuator started, listening on {topic}")

    try:
        client.loop_forever()
    except KeyboardInterrupt:
        print(f"\n[{args.device_name}] Actuator shutting down.")
    finally:
        client.disconnect()


if __name__ == "__main__":
    main()
