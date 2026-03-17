from abc import ABC, abstractmethod
from typing import Dict


class EnvironmentCollector(ABC):
    """
    Abstract baseline for tools collecting runtime metadata
    (e.g hostname, loaded python modules) to inject into the Kest DAG.
    """

    @abstractmethod
    def collect(self) -> Dict[str, str]:
        """Collects and returns key-value string pairs representing runtime environment."""
        pass
