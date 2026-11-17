"""
Adapter for OpenAI and OpenAI-compatible APIs (OpenRouter, Groq, Together, Ollama, vLLM).
"""

import time
import requests
from typing import Tuple, Optional, Dict, Any
from .base import BaseTargetAdapter
from .ssrf import validate_url_ssrf


class OpenAIAdapter(BaseTargetAdapter):
    """
    Adapter communicating with OpenAI or OpenAI-compatible Chat Completions endpoints.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.model = self.model or "gpt-4o-mini"
        default_url = (
            "https://openrouter.ai/api/v1"
            if self.provider == "openrouter"
            else "https://api.openai.com/v1"
        )
        base = (self.base_url or default_url).rstrip("/")
        if base.endswith("/chat/completions"):
            self.endpoint = base
        else:
            self.endpoint = f"{base}/chat/completions"

    def _validate_destination(self) -> Tuple[bool, Optional[str]]:
        # If user is using custom base URL, validate for SSRF unless local network allowed
        if self.base_url:
            return validate_url_ssrf(self.endpoint, allow_local_network=self.allow_local_network)
        return True, None

    def test_connection(self) -> Tuple[bool, str, Optional[int]]:
        """Verify API key and model availability with a lightweight completion request."""
        valid, err = self._validate_destination()
        if not valid:
            return False, f"Endpoint rejected: {err}", None

        if not self.api_key and self.provider != "openai_compatible":
            return False, "API key is required for this provider.", None

        t0 = time.monotonic()
        ping_prompt = "Say 'OK' to confirm connectivity."
        resp, lat = self.send_message(ping_prompt, system_prompt=None)

        if resp.startswith("[ERROR]"):
            return False, resp.replace("[ERROR] ", ""), lat

        latency = lat if lat is not None else round((time.monotonic() - t0) * 1000)
        return True, f"Successfully connected to {self.provider.upper()} model '{self.model}'", latency

    def send_message(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[str, Optional[int]]:
        """Send chat completion request to OpenAI-compatible endpoint."""
        valid, err = self._validate_destination()
        if not valid:
            return f"[ERROR] Request blocked by SSRF protection: {err}", None

        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        if self.provider == "openrouter":
            headers["HTTP-Referer"] = "https://llmguard.local"
            headers["X-Title"] = "LLMGuard Security Suite"

        messages = []
        eff_sys = self.get_effective_system_prompt(system_prompt)
        if eff_sys:
            messages.append({"role": "system", "content": eff_sys})
        messages.append({"role": "user", "content": prompt})

        body: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.2,
        }

        t0 = time.monotonic()
        try:
            resp = requests.post(
                self.endpoint,
                headers=headers,
                json=body,
                timeout=self.timeout
            )
            latency_ms = round((time.monotonic() - t0) * 1000)

            if resp.status_code == 200:
                data = resp.json()
                choices = data.get("choices", [])
                if choices:
                    content = choices[0].get("message", {}).get("content", "")
                    return content or "[Empty response received]", latency_ms
                return "[No choices returned by endpoint]", latency_ms

            status = resp.status_code
            try:
                err_json = resp.json()
                err_msg = err_json.get("error", {}).get("message") or str(err_json)
            except Exception:
                err_msg = resp.text

            if status == 401:
                return f"[ERROR] Authentication failed (HTTP 401): Invalid API key for {self.provider}.", latency_ms
            elif status == 404:
                return f"[ERROR] Model or endpoint not found (HTTP 404): Check model identifier '{self.model}'.", latency_ms
            elif status == 429:
                return f"[ERROR] Rate limit or quota exhausted (HTTP 429): {err_msg}", latency_ms
            return f"[ERROR] Provider error (HTTP {status}): {err_msg}", latency_ms

        except requests.exceptions.Timeout:
            return f"[ERROR] Request timed out after {self.timeout}s.", None
        except requests.exceptions.RequestException as exc:
            return f"[ERROR] Network error contacting {self.endpoint}: {self.sanitize_error(exc)}", None
