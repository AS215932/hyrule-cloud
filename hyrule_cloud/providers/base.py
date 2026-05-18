"""
Base protocols and unified errors for all providers.
"""
from abc import abstractmethod
from typing import Protocol


class ProviderError(Exception):
    """Unified error type for all providers."""
    def __init__(self, provider: str, code: str, message: str, retryable: bool = False):
        self.provider = provider
        self.code = code
        self.retryable = retryable
        super().__init__(f"[{provider}] {code}: {message}")

class Provider(Protocol):
    """Contract that all providers must implement."""
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Return True if provider is accessible."""
        ...
    
    @abstractmethod
    async def close(self) -> None:
        """Close connections and cleanup."""
        ...
