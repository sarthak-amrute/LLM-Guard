"""
Base target adapter class and interface for LLMGuard.
All provider-specific adapters inherit from BaseTargetAdapter.
"""

from abc import ABC, abstractmethod
from typing import Tuple, Optional, Dict, Any, List


class BaseTargetAdapter(ABC):
    """
    Common target-adapter interface allowing LLMGuard to test and probe
    heterogeneous AI models and endpoints through a uniform contract.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.target_id: str = config.get("id", "target-default")
        self.name: str = config.get("name", "Unnamed Target")
        self.provider: str = config.get("provider", "custom")
        self.model: str = config.get("model", "")
        self.api_key: Optional[str] = config.get("api_key")
        self.base_url: Optional[str] = config.get("base_url")
        self.system_prompt: Optional[str] = config.get("system_prompt")
        self.canaries: List[str] = config.get("canaries") or []
        self.timeout: int = config.get("timeout", 45)
        self.allow_local_network: bool = config.get("allow_local_network", False)

    @abstractmethod
    def test_connection(self) -> Tuple[bool, str, Optional[int]]:
        """
        Verify connectivity and credential validity against the upstream target.
        Returns:
            Tuple of (success: bool, message: str, latency_ms: Optional[int])
        """
        pass

    @abstractmethod
    def send_message(self, prompt: str, system_prompt: Optional[str] = None) -> Tuple[str, Optional[int]]:
        """
        Send an adversarial probe prompt to the target.
        Returns:
            Tuple of (response_text: str, latency_ms: Optional[int])
            If an unrecoverable upstream error occurs, response_text starts with '[ERROR]'
        """
        pass

    def get_effective_system_prompt(self, override: Optional[str] = None) -> Optional[str]:
        """Returns the system prompt to apply, giving precedence to run-time override."""
        if override is not None:
            return override
        return self.system_prompt

    def sanitize_error(self, exc: Exception) -> str:
        """Strip raw API keys and internal traces from exception messages."""
        msg = str(exc)
        if self.api_key and len(self.api_key) > 6:
            msg = msg.replace(self.api_key, "[REDACTED_API_KEY]")
        return msg
