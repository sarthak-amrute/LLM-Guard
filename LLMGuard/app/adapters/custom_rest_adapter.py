"""
Adapter for custom REST API endpoints with configurable request/response mappings
and strict SSRF enforcement.
"""

import json
import time
import requests
from typing import Tuple, Optional, Dict, Any
from .base import BaseTargetAdapter
from .ssrf import validate_url_ssrf


def _extract_by_path(data: Any, path: str) -> Any:
    """Extract nested value from dict/list using dot notation or array indexing (e.g., 'choices.0.message.content')."""
    if not path or not isinstance(data, (dict, list)):
        return data

    tokens = path.split(".")
    curr = data
    for token in tokens:
        if isinstance(curr, dict):
            if token in curr:
                curr = curr[token]
            else:
                return None
        elif isinstance(curr, list):
            try:
                idx = int(token)
                curr = curr[idx]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return curr


def _auto_extract_response_text(data: Any) -> str:
    """Best-effort heuristic extraction of response text from common JSON schemas."""
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        for candidate_key in ("response", "reply", "output", "text", "message", "content", "result"):
            if candidate_key in data:
                val = data[candidate_key]
                if isinstance(val, str):
                    return val
                if isinstance(val, dict) and "content" in val:
                    return str(val["content"])
        # Check OpenAI style choices
        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0]
            if isinstance(first, dict):
                msg = first.get("message", {})
                if isinstance(msg, dict) and "content" in msg:
                    return str(msg["content"])
                if "text" in first:
                    return str(first["text"])

        return json.dumps(data, indent=2)

    return str(data)


class CustomRestAdapter(BaseTargetAdapter):
    """
    Adapter communicating with arbitrary custom REST endpoints.
    Allows configuring HTTP method, headers, request template, and response extraction path.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.endpoint_url = (config.get("base_url") or config.get("endpoint_url") or "").strip()
        self.http_method = (config.get("http_method") or "POST").upper()
        self.custom_headers = config.get("headers") or {}
        self.request_template = config.get("request_template")
        self.response_path = config.get("response_path")

    def _validate_ssrf(self) -> Tuple[bool, Optional[str]]:
        return validate_url_ssrf(self.endpoint_url, allow_local_network=self.allow_local_network)

    def test_connection(self) -> Tuple[bool, str, Optional[int]]:
        """Verify reachability and schema extraction for custom endpoint."""
        if not self.endpoint_url:
            return False, "Target endpoint URL is required.", None

        valid, err = self._validate_ssrf()
        if not valid:
            return False, f"Endpoint rejected: {err}", None

        t0 = time.monotonic()
        ping_prompt = "Say 'OK' to confirm connectivity."
        resp, lat = self.send_message(ping_prompt, system_prompt=None)

        if resp.startswith("[ERROR]"):
            return False, resp.replace("[ERROR] ", ""), lat

        latency = lat if lat is not None else round((time.monotonic() - t0) * 1000)
        return True, f"Successfully connected to custom endpoint ({self.endpoint_url})", latency

    def _build_payload(self, prompt: str, system_prompt: Optional[str] = None) -> Any:
        eff_sys = self.get_effective_system_prompt(system_prompt) or ""

        if self.request_template:
            tpl = self.request_template
            if isinstance(tpl, str):
                # Replace placeholders
                rendered = tpl.replace("{{prompt}}", prompt).replace("{prompt}", prompt)
                rendered = rendered.replace("{{system_prompt}}", eff_sys).replace("{system_prompt}", eff_sys)
                try:
                    return json.loads(rendered)
                except Exception:
                    return rendered
            elif isinstance(tpl, dict):
                # Recursive replace in dict
                dumped = json.dumps(tpl)
                dumped = dumped.replace("{{prompt}}", prompt).replace("{prompt}", prompt)
                dumped = dumped.replace("{{system_prompt}}", eff_sys).replace("{system_prompt}", eff_sys)
                return json.loads(dumped)

        # Default payload schema
        payload = {"message": prompt}
        if eff_sys:
            payload["system_prompt"] = eff_sys
        return payload

    def send_message(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[str, Optional[int]]:
        """Send request to the custom REST endpoint and extract normalized response."""
        if not self.endpoint_url:
            return "[ERROR] Target endpoint URL is not configured.", None

        valid, err = self._validate_ssrf()
        if not valid:
            return f"[ERROR] Request blocked by SSRF protection: {err}", None

        # Assemble headers
        headers = {"Content-Type": "application/json"}
        if isinstance(self.custom_headers, dict):
            headers.update(self.custom_headers)
        elif isinstance(self.custom_headers, str):
            try:
                parsed_headers = json.loads(self.custom_headers)
                if isinstance(parsed_headers, dict):
                    headers.update(parsed_headers)
            except Exception:
                pass

        if self.api_key and "Authorization" not in headers:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = self._build_payload(prompt, system_prompt)

        t0 = time.monotonic()
        try:
            # We disallow redirects to prevent open-redirect SSRF bypasses to private networks
            if self.http_method == "GET":
                resp = requests.get(
                    self.endpoint_url,
                    headers=headers,
                    params={"prompt": prompt},
                    timeout=self.timeout,
                    allow_redirects=False
                )
            else:
                resp = requests.post(
                    self.endpoint_url,
                    headers=headers,
                    json=payload if isinstance(payload, (dict, list)) else None,
                    data=payload if isinstance(payload, str) else None,
                    timeout=self.timeout,
                    allow_redirects=False
                )

            latency_ms = round((time.monotonic() - t0) * 1000)

            # Prevent redirect SSRF
            if resp.status_code in (301, 302, 303, 307, 308):
                redirect_target = resp.headers.get("Location", "")
                return f"[ERROR] Request attempted redirect to '{redirect_target}'. Redirects are blocked for security.", latency_ms

            if 200 <= resp.status_code < 300:
                try:
                    data = resp.json()
                    if self.response_path:
                        extracted = _extract_by_path(data, self.response_path)
                        if extracted is not None:
                            return str(extracted), latency_ms
                        return f"[ERROR] Response path '{self.response_path}' not found in target JSON response.", latency_ms
                    return _auto_extract_response_text(data), latency_ms
                except ValueError:
                    return resp.text or "[Empty response]", latency_ms

            return f"[ERROR] Custom target returned HTTP {resp.status_code}: {resp.text[:300]}", latency_ms

        except requests.exceptions.Timeout:
            return f"[ERROR] Request timed out after {self.timeout}s.", None
        except requests.exceptions.RequestException as exc:
            return f"[ERROR] Network error contacting custom target: {self.sanitize_error(exc)}", None
