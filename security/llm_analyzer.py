import asyncio
import json
import os
from datetime import datetime

try:
    import google.generativeai as genai
except ImportError:
    genai = None

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
except ImportError:
    pass


class LLMAnalyzer:
    """
    Async Gemini-based deep threat analysis.

    When the rule engine flags a packet as suspicious with low confidence,
    this module sends the context to Gemini for deeper reasoning. Runs in
    a background asyncio task so the main monitoring loop is never blocked.
    """

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "")
        self.model_name = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
        self._model = None
        self._available = False
        self._init_model()

    def _init_model(self):
        if not genai:
            print("[LLM] google-generativeai not installed. LLM analysis disabled.")
            return
        if not self.api_key:
            print("[LLM] GEMINI_API_KEY not set. LLM analysis disabled.")
            return

        try:
            genai.configure(api_key=self.api_key)
            self._model = genai.GenerativeModel(self.model_name)
            self._available = True
            print(f"[LLM] Gemini ({self.model_name}) initialized successfully.")
        except Exception as e:
            print(f"[LLM] Failed to initialize Gemini: {e}")

    @property
    def available(self):
        return self._available

    def _build_prompt(self, packet_dict, rules_triggered, device_history=None):
        history_section = ""
        if device_history:
            recent = device_history[-10:]
            history_lines = "\n".join(
                f"  - [{m['timestamp']}] topic={m['topic']} payload={m['payload']}"
                for m in recent
            )
            history_section = f"""
Recent message history from this device:
{history_lines}
"""

        rules_section = "\n".join(
            f"  - {r['rule_name']}: {r['detail']} (severity={r['severity']}, confidence={r['confidence']})"
            for r in rules_triggered
        )

        return f"""You are an IoT network security analyst for a smart-home network.

A suspicious MQTT packet has been flagged by the intrusion detection system's rule engine.
Analyze this packet and provide a threat assessment.

## Flagged Packet
- Topic: {packet_dict['topic']}
- Payload: {packet_dict['payload']}
- Source Client ID: {packet_dict['client_id']}
- Source IP: {packet_dict['source_ip']}
- Timestamp: {packet_dict['timestamp']}

## Rules Triggered
{rules_section}
{history_section}
## Network Context
This is a smart-home IoT network with:
- 10 sensors (light, temperature, sound, motion, camera, smart-plug, air-purifier, doorbell, smoke/gas, speaker)
- 10 actuators (one per sensor)
- A central CPU/controller at 10.0.0.100 that processes sensor data and sends commands
- Trusted IP range: 10.0.0.1-10.0.0.21 (devices), 10.0.0.99 (IDS), 10.0.0.100 (CPU)
- Communication: MQTT on port 1883

## Required Response Format
Respond ONLY with valid JSON (no markdown fences, no extra text):
{{
    "threat_level": "none|low|medium|high|critical",
    "threat_type": "none|flooding|malformed|spoofing|novel",
    "explanation": "detailed explanation of the threat and your reasoning",
    "is_threat": true or false,
    "recommended_actions": ["action1", "action2"],
    "confidence": 0.0 to 1.0
}}
## Threat Type Classification Rules
- Use "none" when no threat is detected (is_threat must be false)
- Use "flooding" for high-frequency packet storms, DoS, or connection exhaustion attacks
- Use "malformed" for structurally invalid topics, malformed payloads, or protocol violations
- Use "spoofing" for IP/client ID impersonation, identity forgery, or unauthorized device masquerading
- Use "novel" for any confirmed or suspected threat that does not clearly fit the above three categories
- threat_type must be exactly one of: none, flooding, malformed, spoofing, novel — no other values are permitted
"""

    async def analyze(self, packet_dict, rules_triggered, device_history=None):
        """
        Perform async LLM analysis on a suspicious packet.
        Returns a dict with the analysis result, or a fallback if LLM is unavailable.
        """
        if not self._available:
            return self._fallback_analysis(rules_triggered)

        prompt = self._build_prompt(packet_dict, rules_triggered, device_history)

        try:
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, lambda: self._model.generate_content(prompt)
            )
            text = response.text.strip()

            if text.startswith("```"):
                text = text.split("\n", 1)[1] if "\n" in text else text[3:]
                if text.endswith("```"):
                    text = text[:-3]
                text = text.strip()

            result = json.loads(text)
            result["source"] = "gemini"
            result["analyzed_at"] = datetime.now().isoformat()
            return result

        except json.JSONDecodeError as e:
            print(f"[LLM] Failed to parse Gemini response as JSON: {e}")
            print(f"[LLM] Raw response: {text[:300]}")
            return self._fallback_analysis(rules_triggered)
        except Exception as e:
            print(f"[LLM] Gemini API error: {e}")
            return self._fallback_analysis(rules_triggered)

    def _fallback_analysis(self, rules_triggered):
        """Rule-based fallback when Gemini is unavailable."""
        max_severity = max((r["severity"] for r in rules_triggered), default=0)

        if max_severity >= 9:
            level = "critical"
        elif max_severity >= 7:
            level = "high"
        elif max_severity >= 5:
            level = "medium"
        else:
            level = "low"

        rule_names = [r["rule_name"] for r in rules_triggered]
        details = [r["detail"] for r in rules_triggered]

        return {
            "threat_level": level,
            "threat_type": rule_names[0] if rule_names else "unknown",
            "explanation": f"Fallback analysis (LLM unavailable). Rules triggered: {'; '.join(details)}",
            "is_threat": max_severity >= 5,
            "recommended_actions": self._suggest_actions(rule_names, max_severity),
            "confidence": min((r["confidence"] for r in rules_triggered), default=0.5),
            "source": "fallback",
            "analyzed_at": datetime.now().isoformat(),
        }

    def _suggest_actions(self, rule_names, severity):
        actions = []
        if severity >= 7:
            actions.append("block_device")
        if "direct_actuator_access" in rule_names:
            actions.append("reset_actuator")
        if "value_range" in rule_names:
            actions.append("block_device")
        if severity >= 5:
            actions.append("increase_monitoring")
        if severity >= 9:
            actions.append("network_isolate")
        return actions or ["increase_monitoring"]
