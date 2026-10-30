"""
Self-Hosted Ollama LLM Service for CASOC NIDS
Connects to local Ollama server (http://localhost:11434) without any cloud API keys.
Performs autonomous incident analysis, MITRE ATT&CK reasoning, SOAR playbook synthesis,
and conversational SOC Copilot Q&A.
"""

import json
import os
import time
import urllib.request
import urllib.error

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2")


class OllamaService:
    def __init__(self, base_url=OLLAMA_BASE_URL, default_model=DEFAULT_MODEL):
        self.base_url = base_url.rstrip("/")
        self.preferred_model = default_model
        self.cached_model = None
        self.last_check = 0

    def is_available(self, timeout=1.5):
        """Checks if the local Ollama daemon is active and responding."""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", headers={"User-Agent": "CASOC-OllamaClient"})
            with urllib.request.urlopen(req, timeout=timeout) as res:
                return res.status == 200
        except Exception:
            return False

    def get_available_models(self, timeout=2.0):
        """Returns list of installed local Ollama models."""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", headers={"User-Agent": "CASOC-OllamaClient"})
            with urllib.request.urlopen(req, timeout=timeout) as res:
                data = json.loads(res.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]
                return models
        except Exception as e:
            return []

    def get_active_model(self):
        """Picks the best available installed model: llama3.2 > mistral > qwen2.5 > first available."""
        now = time.time()
        if self.cached_model and (now - self.last_check < 30):
            return self.cached_model

        models = self.get_available_models()
        self.last_check = now

        if not models:
            self.cached_model = self.preferred_model
            return self.preferred_model

        # Check preference hierarchy
        for pref in [self.preferred_model, "llama3.2:latest", "llama3.2", "mistral", "qwen2.5:7b", "qwen2.5:1.5b", "qwen2.5"]:
            for m in models:
                if m == pref or m.startswith(pref.split(":")[0]):
                    self.cached_model = m
                    return m

        self.cached_model = models[0]
        return models[0]

    def generate(self, prompt, system_prompt=None, model=None, temperature=0.2, max_tokens=250, timeout=120):
        """
        Sends generation request to local Ollama API.
        """
        target_model = model or self.get_active_model()
        payload = {
            "model": target_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }
        if system_prompt:
            payload["system"] = system_prompt

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{self.base_url}/api/generate",
                data=data,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as res:
                res_data = json.loads(res.read().decode("utf-8"))
                return {
                    "success": True,
                    "response": res_data.get("response", "").strip(),
                    "model": target_model,
                    "total_duration_ms": round(res_data.get("total_duration", 0) / 1e6, 2),
                    "eval_count": res_data.get("eval_count", 0)
                }
        except urllib.error.URLError as e:
            return {
                "success": False,
                "error": f"Ollama connection error: {e}",
                "model": target_model
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "model": target_model
            }

    def analyze_incident(self, incident_dict):
        """
        Prompts Ollama to act as a Senior Tier-3 SOC Analyst and provide a structured
        incident investigation report grounded in live flow telemetry and XAI features.
        """
        category = incident_dict.get("category", "Threat Incident")
        src_ip = incident_dict.get("src_ip", "Unknown")
        dst_ip = incident_dict.get("dst_ip", "Unknown")
        severity = incident_dict.get("threat_severity", "HIGH")
        confidence = incident_dict.get("confidence", 95.0)
        mitre = incident_dict.get("mitre_attack", {})
        xai = incident_dict.get("xai", [])
        raw_feat = incident_dict.get("raw_features", {})

        system_prompt = (
            "You are an expert Cybersecurity Operations Center (SOC) Tier-3 AI Analyst. "
            "You provide concise, highly technical, action-oriented threat analyses based on "
            "network flow telemetry, Deep Packet Inspection (DPI), and MITRE ATT&CK tactics."
        )

        user_prompt = f"""
Investigate the following confirmed security incident intercepted by CASOC NIDS:
- Threat Type: {category} (Severity: {severity}, Confidence: {confidence}%)
- Attacker IP: {src_ip} -> Target IP: {dst_ip}
- MITRE ATT&CK: {mitre.get('technique_id', 'T1498')} - {mitre.get('technique_name', 'Network Attack')}
- TreeSHAP Key Indicators: {json.dumps(xai)}
- Key Flow Telemetry: {json.dumps(raw_feat)}

Provide a concise 3-part operational assessment in under 150 words:
1. Technical Root Cause & Behavioral Vector
2. Immediate Perimeter Containment & Firewall Rule (iptables / ufw)
3. Eradication & Long-Term Threat Hunting Recommendation
"""
        res = self.generate(user_prompt, system_prompt=system_prompt, temperature=0.1, max_tokens=250)
        return res

    def chat_soc_copilot(self, query, context=None):
        """
        Interactive SOC Q&A with real-time telemetry grounding, speaking directly to the Admin.
        """
        system_prompt = (
            "You are CASOC Autonomous AI Copilot, a conversational, expert cybersecurity AI assistant. "
            "You are speaking directly to the Admin of the CASOC Security Operations Center. "
            "Always address the user warmly and authoritatively as Admin. "
            "Provide direct, helpful, natural responses in under 120 words using clean markdown formatting. "
            "You have complete knowledge of this project (LightGBM 21 features, Isolation Forest, TreeSHAP XAI, "
            "DPI signatures, Active Defense honeypot sandbox, and attack simulation)."
        )

        context_str = ""
        if context:
            context_str = f"\n\nLive Telemetry Context:\n{json.dumps(context, default=str)}"

        prompt = f"Admin: {query}{context_str}"
        return self.generate(prompt, system_prompt=system_prompt, temperature=0.2, max_tokens=120, timeout=15)


global_ollama = OllamaService()
