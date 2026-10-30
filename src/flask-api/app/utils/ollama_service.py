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

import json
import os
import time
import urllib.request
import urllib.error

OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("OLLAMA_MODEL", None)
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")


class OllamaService:
    def __init__(self, base_url=OLLAMA_BASE_URL, default_model=DEFAULT_MODEL):
        self.base_url = base_url.rstrip("/")
        self.preferred_model = default_model
        self.cached_model = None
        self.last_check = 0

    def is_available(self, timeout=2.0):
        """Checks if any LLM backend (Groq, OpenAI, or local Ollama) is active."""
        if GROQ_API_KEY or OPENAI_API_KEY:
            return True
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", headers={"User-Agent": "CASOC-Client"})
            with urllib.request.urlopen(req, timeout=timeout) as res:
                return res.status == 200
        except Exception:
            return False

    def get_available_models(self, timeout=2.0):
        """Returns list of installed local Ollama models."""
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags", headers={"User-Agent": "CASOC-Client"})
            with urllib.request.urlopen(req, timeout=timeout) as res:
                data = json.loads(res.read().decode("utf-8"))
                models = [m.get("name", "") for m in data.get("models", [])]
                return models
        except Exception:
            return []

    def get_active_model(self):
        """Picks the fastest and best available installed model: qwen2.5:1.5b > llama3.2 > mistral."""
        if self.preferred_model:
            return self.preferred_model

        now = time.time()
        if self.cached_model and (now - self.last_check < 30):
            return self.cached_model

        models = self.get_available_models()
        self.last_check = now

        if not models:
            self.cached_model = "qwen2.5:1.5b"
            return self.cached_model

        # Prioritize qwen2.5:1.5b for fast sub-second CPU response if installed, then llama3.2
        for pref in ["qwen2.5:1.5b", "qwen2.5:latest", "qwen2.5", "llama3.2:latest", "llama3.2", "mistral"]:
            for m in models:
                if m == pref or m.startswith(pref.split(":")[0]):
                    self.cached_model = m
                    return m

        self.cached_model = models[0]
        return models[0]

    def _call_cloud_gpt(self, prompt, system_prompt=None, temperature=0.3, max_tokens=400, timeout=30):
        """Calls Groq or OpenAI chat completions API if credentials exist."""
        api_key = GROQ_API_KEY or OPENAI_API_KEY
        if not api_key:
            return None

        if GROQ_API_KEY:
            endpoint = "https://api.groq.com/openai/v1/chat/completions"
            model = os.environ.get("GROQ_MODEL", "llama-3.1-8b-instant")
        else:
            endpoint = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/") + "/chat/completions"
            model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens
        }

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                endpoint,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}"
                }
            )
            with urllib.request.urlopen(req, timeout=timeout) as res:
                res_data = json.loads(res.read().decode("utf-8"))
                choice = res_data.get("choices", [{}])[0]
                content = choice.get("message", {}).get("content", "").strip()
                return {
                    "success": True,
                    "response": content,
                    "model": model,
                    "provider": "Cloud GPT"
                }
        except Exception as e:
            print(f"[OllamaService] Cloud GPT error: {e}")
            return None

    def generate(self, prompt, system_prompt=None, model=None, temperature=0.2, max_tokens=300, timeout=90):
        """
        Sends generation request to Cloud GPT (if configured) or local Ollama API.
        """
        # 1. Try cloud LLM if configured
        cloud_res = self._call_cloud_gpt(prompt, system_prompt=system_prompt, temperature=temperature, max_tokens=max_tokens)
        if cloud_res and cloud_res.get("success"):
            return cloud_res

        # 2. Try local Ollama
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
        Prompts Ollama/GPT to act as a Senior Tier-3 SOC Analyst and provide a structured
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
        Interactive SOC Q&A with real-time telemetry grounding, operating dynamically like GPT.
        """
        system_prompt = (
            "You are the CASOC Autonomous AI Security Copilot, an expert cybersecurity GPT assistant. "
            "You are speaking directly to the Security Operations Center (SOC) Admin. "
            "Address the user naturally as Admin. "
            "Think, reason, and converse dynamically like ChatGPT / GPT-4. "
            "Never reply with predefined or robotic canned templates. "
            "Provide insightful, concise, direct answers using clean markdown formatting (bullet points, bold headers). "
            "Ground your reasoning in the live network telemetry, firewall block status, and system architecture facts provided below."
        )

        context_str = ""
        if context:
            context_str = f"\n\n[LIVE CASOC SECURITY CONTEXT & TELEMETRY]\n{json.dumps(context, indent=2, default=str)}"

        prompt = f"Admin Request: {query}{context_str}\n\nCopilot GPT Response:"
        return self.generate(prompt, system_prompt=system_prompt, temperature=0.3, max_tokens=200, timeout=120)


global_ollama = OllamaService()
