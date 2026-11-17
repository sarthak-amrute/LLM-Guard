"""
Adapter for the local TechMart Support demonstration target.
Preserves existing SECURE / VULNERABLE mode switching and /chat endpoint.
"""

import time
import requests
from typing import Tuple, Optional, Dict, Any
from .base import BaseTargetAdapter


class TechMartAdapter(BaseTargetAdapter):
    """
    Adapter communicating with TechMart Customer Support AI demo service.
    Default runs at http://127.0.0.1:8000.
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = (self.base_url or "http://127.0.0.1:8000").rstrip("/")
        self.chat_url = f"{self.base_url}/chat"
        self.mode_url = f"{self.base_url}/mode"

    def get_mode(self) -> str:
        """Query TechMart mode (SECURE / VULNERABLE / UNKNOWN)."""
        try:
            resp = requests.get(self.mode_url, timeout=5)
            if resp.status_code == 200:
                return resp.json().get("mode", "UNKNOWN")
        except Exception:
            pass
        return "UNKNOWN"

    def set_mode(self, mode: str) -> Optional[str]:
        """Switch TechMart operating mode."""
        mode_upper = mode.strip().upper()
        try:
            resp = requests.post(
                self.mode_url,
                json={"mode": mode_upper},
                timeout=5
            )
            if resp.status_code == 200:
                return resp.json().get("mode", mode_upper)
        except Exception:
            pass
        return None

    def test_connection(self) -> Tuple[bool, str, Optional[int]]:
        """Verify reachability of TechMart Support API."""
        t0 = time.monotonic()
        try:
            resp = requests.get(self.mode_url, timeout=5)
            latency_ms = round((time.monotonic() - t0) * 1000)
            if resp.status_code == 200:
                current_mode = resp.json().get("mode", "UNKNOWN")
                return True, f"Connected to TechMart API (Mode: {current_mode})", latency_ms
            return False, f"TechMart returned HTTP {resp.status_code}", latency_ms
        except requests.exceptions.ConnectionError:
            return False, f"Could not connect to TechMart service at {self.base_url}. Ensure server is running on port 8000.", None
        except Exception as exc:
            return False, f"Connection check failed: {self.sanitize_error(exc)}", None

    def send_message(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[str, Optional[int]]:
        """Send attack prompt to TechMart Support /chat endpoint."""
        max_retries = 2
        last_error = None

        for attempt in range(1, max_retries + 1):
            t0 = time.monotonic()
            try:
                resp = requests.post(
                    self.chat_url,
                    json={"message": prompt},
                    timeout=self.timeout
                )
                latency_ms = round((time.monotonic() - t0) * 1000)

                if resp.status_code == 200:
                    data = resp.json()
                    response_text = data.get("response", "")
                    return response_text, latency_ms

                last_error = f"HTTP {resp.status_code}: {resp.text}"

            except requests.exceptions.RequestException as exc:
                last_error = str(exc)

            if attempt < max_retries:
                time.sleep(1.5)

        return f"[ERROR] TechMart API failed: {last_error}", None
