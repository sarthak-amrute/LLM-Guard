"""
Adapter for Anthropic Claude API (Messages API).
"""

import time
import requests
from typing import Tuple, Optional, Dict, Any
from .base import BaseTargetAdapter
from .ssrf import validate_url_ssrf


class AnthropicAdapter(BaseTargetAdapter):
    """
    Adapter communicating with Anthropic Claude Messages API.
    Supports claude-3-5-sonnet-20241022, claude-3-haiku-20240307, etc.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.model = self.model or "claude-3-5-sonnet-20241022"
        base = (self.base_url or "https://api.anthropic.com/v1").rstrip("/")
        if base.endswith("/messages"):
            self.endpoint = base
        else:
            self.endpoint = f"{base}/messages"

    def _validate_destination(self) -> Tuple[bool, Optional[str]]:
        if self.base_url:
            return validate_url_ssrf(self.endpoint, allow_local_network=self.allow_local_network)
        return True, None

    def test_connection(self) -> Tuple[bool, str, Optional[int]]:
        """Verify Anthropic API key and model access."""
        valid, err = self._validate_destination()
        if not valid:
            return False, f"Endpoint rejected: {err}", None

        if not self.api_key:
            return False, "Anthropic API key is required.", None

        t0 = time.monotonic()
        ping_prompt = "Say 'OK' to confirm connectivity."
        resp, lat = self.send_message(ping_prompt, system_prompt=None)

        if resp.startswith("[ERROR]"):
            return False, resp.replace("[ERROR] ", ""), lat

        latency = lat if lat is not None else round((time.monotonic() - t0) * 1000)
        return True, f"Successfully connected to Anthropic model '{self.model}'", latency

    def send_message(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[str, Optional[int]]:
        """Send message to Anthropic Messages endpoint."""
        valid, err = self._validate_destination()
        if not valid:
            return f"[ERROR] Request blocked by SSRF protection: {err}", None

        if not self.api_key:
            return "[ERROR] Anthropic API key is missing.", None

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        body: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": prompt}
            ],
        }

        eff_sys = self.get_effective_system_prompt(system_prompt)
        if eff_sys:
            body["system"] = eff_sys

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
                content_blocks = data.get("content", [])
                text_parts = [b.get("text", "") for b in content_blocks if b.get("type") == "text"]
                return "".join(text_parts) or "[Empty response received]", latency_ms

            status = resp.status_code
            try:
                err_data = resp.json().get("error", {})
                err_msg = err_data.get("message", resp.text)
                err_type = err_data.get("type", "unknown_error")
            except Exception:
                err_msg = resp.text
                err_type = "unknown_error"

            if status == 401:
                return f"[ERROR] Anthropic Authentication failed (HTTP 401): Invalid API key.", latency_ms
            elif status == 403:
                return f"[ERROR] Anthropic Permission denied (HTTP 403): {err_msg}", latency_ms
            elif status == 404:
                return f"[ERROR] Anthropic Model not found (HTTP 404): Model '{self.model}' is unavailable or typo in model name.", latency_ms
            elif status == 429:
                return f"[ERROR] Anthropic Rate limit exceeded (HTTP 429): {err_msg}", latency_ms
            return f"[ERROR] Anthropic error ({err_type}, HTTP {status}): {err_msg}", latency_ms

        except requests.exceptions.Timeout:
            return f"[ERROR] Anthropic request timed out after {self.timeout}s.", None
        except requests.exceptions.RequestException as exc:
            return f"[ERROR] Network error contacting Anthropic API: {self.sanitize_error(exc)}", None
