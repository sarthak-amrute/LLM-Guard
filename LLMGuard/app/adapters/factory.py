"""
Target Adapter Factory for LLMGuard.
"""

from typing import Dict, Any
from .base import BaseTargetAdapter
from .techmart_adapter import TechMartAdapter
from .gemini_adapter import GeminiAdapter
from .openai_adapter import OpenAIAdapter
from .anthropic_adapter import AnthropicAdapter
from .custom_rest_adapter import CustomRestAdapter


def create_adapter(config: Dict[str, Any]) -> BaseTargetAdapter:
    """Create and return a provider-specific adapter instance for the given target configuration."""
    provider = (config.get("provider") or "custom").lower()

    if provider == "techmart":
        return TechMartAdapter(config)
    elif provider == "gemini":
        return GeminiAdapter(config)
    elif provider in ("openai", "openrouter", "openai_compatible"):
        return OpenAIAdapter(config)
    elif provider == "anthropic":
        return AnthropicAdapter(config)
    elif provider in ("custom", "custom_rest"):
        return CustomRestAdapter(config)
    else:
        # Default fallback to custom REST
        return CustomRestAdapter(config)
