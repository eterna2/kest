from abc import ABC, abstractmethod
from typing import Any, Optional


class CacheProvider(ABC):
    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        pass

    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        pass


class SimpleCache(CacheProvider):
    """
    In-memory cache for local verification and Claim Check pattern simulation.
    """

    def __init__(self):
        self._data = {}

    def get(self, key: str) -> Optional[Any]:
        return self._data.get(key)

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        self._data[key] = value
