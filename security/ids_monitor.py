import asyncio
import threading
from collections import defaultdict

import paho.mqtt.client as mqtt

from security.utils import PacketRecord, timestamp_readable
from security.firewall import Firewall, FirewallVerdict
from security.rule_engine import RuleEngine
from security.llm_analyzer import LLMAnalyzer
from security.decision_engine import DecisionEngine


class IDSMonitor:
    """
    Core IDS listener. Subscribes to every MQTT topic (#) on the broker,
    and feeds each message through the security pipeline:
      Firewall -> Rule Engine -> (async LLM) -> Decision Engine
    """

    def __init__(self, broker_ip, broker_port=1883, report_generator=None):
        self.broker_ip = broker_ip
        self.broker_port = broker_port

        self.client = mqtt.Client(client_id="ids-node")
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message

        self.firewall = Firewall()
        self.rule_engine = RuleEngine()
        self.llm_analyzer = LLMAnalyzer()
        self.decision_engine = DecisionEngine(self.client, report_generator)

        self._device_history = defaultdict(list)
        self._stats = {
            "packets_processed": 0,
            "packets_passed": 0,
            "packets_flagged": 0,
            "packets_blocked": 0,
        }

        self._loop = asyncio.new_event_loop()
        self._loop_thread = threading.Thread(target=self._run_async_loop, daemon=True)

    def _run_async_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            client.subscribe("#")
            print(f"[IDS] Connected to broker {self.broker_ip}:{self.broker_port}, subscribed to all topics")
        else:
            print(f"[IDS] Connection failed with code {rc}")

    def _on_message(self, client, userdata, message):
        topic = message.topic

        if topic.startswith("security/") or topic.startswith("metrics/"):
            return

        payload = message.payload.decode(errors="replace")
        client_id = self._resolve_client_id(topic)
        source_ip = self._resolve_source_ip(client_id)

        packet = PacketRecord(
            topic=topic,
            payload=payload,
            client_id=client_id,
            source_ip=source_ip,
        )

        self._stats["packets_processed"] += 1
        self._device_history[client_id].append(packet.to_dict())
        if len(self._device_history[client_id]) > 100:
            self._device_history[client_id] = self._device_history[client_id][-50:]

        fw_verdict, fw_reasons = self.firewall.check(packet)

        if fw_verdict == FirewallVerdict.BLOCK:
            self._stats["packets_blocked"] += 1
            self._log(
                "BLOCK",
                f"Firewall blocked {client_id} on {topic}: {'; '.join(fw_reasons)}",
            )
            self._handle_block(packet, fw_reasons)
            return

        if fw_verdict == FirewallVerdict.FLAG:
            self._stats["packets_flagged"] += 1
            self._log(
                "FLAG",
                f"Firewall flagged {client_id} on {topic}: {'; '.join(fw_reasons)}",
            )

        rules_triggered, severity, confidence, needs_llm = self.rule_engine.evaluate(packet)

        if not rules_triggered and fw_verdict == FirewallVerdict.PASS:
            self._stats["packets_passed"] += 1
            return

        if fw_reasons:
            for reason in fw_reasons:
                rules_triggered.append({
                    "rule_name": "firewall",
                    "triggered": True,
                    "severity": 6 if fw_verdict == FirewallVerdict.FLAG else 8,
                    "confidence": 0.8,
                    "detail": reason,
                })
                severity = max(severity, 6)
                confidence = min(confidence, 0.8)
                needs_llm = True

        if needs_llm and self.llm_analyzer.available:
            self._log(
                "LLM",
                f"Escalating to Gemini: {client_id} on {topic} (severity={severity})",
            )
            history = self._device_history.get(client_id, [])
            asyncio.run_coroutine_threadsafe(
                self._async_llm_pipeline(packet, rules_triggered, severity, confidence, history),
                self._loop,
            )
        else:
            llm_result = None
            if needs_llm and not self.llm_analyzer.available:
                llm_result = self.llm_analyzer._fallback_analysis(rules_triggered)
            verdict, threat = self.decision_engine.decide(
                packet, rules_triggered, severity, confidence, llm_result
            )
            self._log_verdict(verdict, packet, threat)

    async def _async_llm_pipeline(self, packet, rules_triggered, severity, confidence, history):
        """Run LLM analysis asynchronously and then feed result to decision engine."""
        try:
            llm_result = await self.llm_analyzer.analyze(
                packet.to_dict(), rules_triggered, history
            )
            verdict, threat = self.decision_engine.decide(
                packet, rules_triggered, severity, confidence, llm_result
            )
            self._log_verdict(verdict, packet, threat)
        except Exception as e:
            print(f"[IDS] Async LLM pipeline error: {e}")
            verdict, threat = self.decision_engine.decide(
                packet, rules_triggered, severity, confidence, None
            )
            self._log_verdict(verdict, packet, threat)

    def _handle_block(self, packet, reasons):
        """When firewall blocks a packet, create a high-severity threat directly."""
        rules = [{
            "rule_name": "firewall_block",
            "triggered": True,
            "severity": 9,
            "confidence": 0.95,
            "detail": "; ".join(reasons),
        }]
        self.decision_engine.decide(packet, rules, 9, 0.95, None)

    def _resolve_client_id(self, topic):
        """Infer the publishing client from the topic using the topic-device map."""
        from security.utils import load_config
        try:
            topics = load_config("mqtt_topics.json")
            device_map = topics.get("topic_to_device_map", {})
            device_key = device_map.get(topic)
            if device_key:
                config = load_config("network_config.json")
                dev = config["devices"].get(device_key, {})
                dev_type = dev.get("type", "")
                name = dev.get("name", device_key)
                if dev_type == "sensor":
                    return f"{name}-sensor"
                elif dev_type == "actuator":
                    return f"{name}-actuator"
                elif dev_type == "cpu":
                    return dev.get("client_id", "cpu-controller")
        except Exception:
            pass
        return "unknown"

    def _resolve_source_ip(self, client_id):
        """Look up the expected IP for a client ID from network config."""
        from security.utils import load_config
        try:
            config = load_config("network_config.json")
            for dev in config["devices"].values():
                name = dev.get("name", "")
                dev_type = dev.get("type", "")
                cid = dev.get("client_id", "")
                expected_cid = ""
                if dev_type == "sensor":
                    expected_cid = f"{name}-sensor"
                elif dev_type == "actuator":
                    expected_cid = f"{name}-actuator"
                elif cid:
                    expected_cid = cid
                if expected_cid == client_id:
                    return dev.get("ip", "unknown")
        except Exception:
            pass
        return "unknown"

    def _log(self, level, message):
        print(f"[IDS] [{timestamp_readable()}] [{level}] {message}")

    def _log_verdict(self, verdict, packet, threat):
        if verdict == DecisionEngine.SAFE:
            return
        if verdict == DecisionEngine.SUSPICIOUS:
            self._log("SUSPICIOUS", f"{packet.client_id} on {packet.topic}: {packet.payload[:60]}")
        elif verdict == DecisionEngine.THREAT:
            self._log(
                "THREAT",
                f"{threat.severity_label} from {packet.client_id} on {packet.topic} "
                f"-> action: {threat.action_taken}",
            )

    def start(self):
        """Connect to broker and begin monitoring."""
        self._loop_thread.start()
        self.client.connect(self.broker_ip, self.broker_port, 60)
        print(f"[IDS] Starting IDS monitor on {self.broker_ip}:{self.broker_port}")
        self.client.loop_forever()

    def stop(self):
        self.client.disconnect()
        self._loop.call_soon_threadsafe(self._loop.stop)

    def get_stats(self):
        return {
            **self._stats,
            "firewall": self.firewall.get_status(),
            "decisions": self.decision_engine.get_stats(),
        }
