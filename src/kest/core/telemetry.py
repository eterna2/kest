from abc import ABC, abstractmethod

from kest.core.models import KestPassport


class TelemetryExporter(ABC):
    """
    Abstract interface for capturing and exporting finalized
    Kest passports to an external system, like SQLite, standard out,
    or a distributed Spanner database.
    """

    @abstractmethod
    def export(self, passport: KestPassport) -> None:
        """Exports the finalized Kest passport."""
        pass
