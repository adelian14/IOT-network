import time
from collections import defaultdict
from security.utils import load_config, timestamp_readable


class FirewallVerdict:
    PASS = "PASS"
    FLAG = "FLAG"
    BLOCK = "BLOCK"


class Firewall:
    """
    Application-level MQTT firewall.

    Checks each message against:
      - IP whitelist/blacklist
      - Per-device rate limits (sliding window)
      - Client ID device authentication
      - Payload size limits
    """

    def __init__(self):
        self.fw_rules = load_config("firewall_rules.json")
        self.network_config = load_config("network_config.json")

        self.allowed_ips = set(self.fw_rules["allowed_ips"])
        self.blocked_ips = set(self.fw_rules["blocked_ips"])
        self.max_payload_size = self.fw_rules["max_payload_size_bytes"]
        self.rate_limits = self.fw_rules["rate_limits"]
        self.block_duration = self.fw_rules["block_duration_seconds"]

        self._known_client_ids = self._build_client_id_set()
        self._message_log = defaultdict(list)
        self._dynamic_blocks = {}

    def _build_client_id_set(self):
        """Build a set of expected MQTT client IDs from network config."""
        ids = set()
        for dev_key, dev in self.network_config["devices"].items():
            dev_type = dev.get("type", "")
            name = dev.get("name", dev_key)
            if dev_type == "sensor":
                ids.add(f"{name}-sensor")
            elif dev_type == "actuator":
                ids.add(f"{name}-actuator")
            elif dev_type == "cpu":
                ids.add(dev.get("client_id", "cpu-controller"))
        ids.add("ids-node")
        return ids

    def check(self, packet):
        """
        Run all firewall checks on a PacketRecord.
        Returns (verdict, reasons_list).
        """
        reasons = []
        verdict = FirewallVerdict.PASS

        ip_result = self._check_ip(packet.source_ip)
        if ip_result:
            reasons.append(ip_result)
            verdict = FirewallVerdict.BLOCK

        if verdict != FirewallVerdict.BLOCK:
            dyn_result = self._check_dynamic_block(packet.source_ip, packet.client_id)
            if dyn_result:
                reasons.append(dyn_result)
                verdict = FirewallVerdict.BLOCK

        if verdict != FirewallVerdict.BLOCK:
            rate_result = self._check_rate_limit(packet.client_id)
            if rate_result:
                reasons.append(rate_result)
                verdict = FirewallVerdict.FLAG

        client_result = self._check_client_id(packet.client_id)
        if client_result:
            reasons.append(client_result)
            if verdict == FirewallVerdict.PASS:
                verdict = FirewallVerdict.FLAG

        size_result = self._check_payload_size(packet.payload)
        if size_result:
            reasons.append(size_result)
            if verdict == FirewallVerdict.PASS:
                verdict = FirewallVerdict.FLAG

        return verdict, reasons

    def _check_ip(self, ip):
        if ip in self.blocked_ips:
            return f"IP {ip} is in static blacklist"
        if ip != "unknown" and ip not in self.allowed_ips:
            return f"IP {ip} is not in whitelist"
        return None

    def _check_dynamic_block(self, ip, client_id):
        now = time.time()
        for key in [ip, client_id]:
            if key in self._dynamic_blocks:
                if now < self._dynamic_blocks[key]:
                    return f"'{key}' is dynamically blocked until {time.ctime(self._dynamic_blocks[key])}"
                else:
                    del self._dynamic_blocks[key]
        return None

    def _check_rate_limit(self, client_id):
        now = time.time()
        self._message_log[client_id].append(now)

        device_type = "default"
        if client_id.endswith("-sensor"):
            device_type = "sensor"
        elif client_id.endswith("-actuator"):
            device_type = "actuator"
        elif client_id == "cpu-controller":
            device_type = "cpu"

        limits = self.rate_limits.get(device_type, self.rate_limits["default"])
        window = limits["window_seconds"]
        max_msgs = limits["max_messages"]

        self._message_log[client_id] = [
            t for t in self._message_log[client_id] if now - t < window
        ]

        count = len(self._message_log[client_id])
        if count > max_msgs:
            return (
                f"Rate limit exceeded for '{client_id}': "
                f"{count}/{max_msgs} msgs in {window}s window"
            )
        return None

    def _check_client_id(self, client_id):
        if client_id == "unknown":
            return None
        if client_id not in self._known_client_ids:
            return f"Unknown client ID: '{client_id}'"
        return None

    def _check_payload_size(self, payload):
        size = len(payload.encode("utf-8")) if payload else 0
        if size > self.max_payload_size:
            return f"Payload size {size}B exceeds limit {self.max_payload_size}B"
        return None

    def block_device(self, identifier, duration=None):
        """Dynamically block a device by IP or client ID."""
        if duration is None:
            duration = self.block_duration
        self._dynamic_blocks[identifier] = time.time() + duration
        print(f"[FIREWALL] [{timestamp_readable()}] Blocked '{identifier}' for {duration}s")

    def unblock_device(self, identifier):
        if identifier in self._dynamic_blocks:
            del self._dynamic_blocks[identifier]
            print(f"[FIREWALL] [{timestamp_readable()}] Unblocked '{identifier}'")

    def get_status(self):
        return {
            "static_blocked": list(self.blocked_ips),
            "dynamic_blocked": {
                k: time.ctime(v) for k, v in self._dynamic_blocks.items()
            },
            "tracked_clients": len(self._message_log),
        }
