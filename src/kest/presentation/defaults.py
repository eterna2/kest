import io
import json
import socket
import sqlite3
import sys
from typing import Optional

from kest.core.environment import EnvironmentCollector
from kest.core.models import KestPassport
from kest.core.telemetry import TelemetryExporter


class HostnameCollector(EnvironmentCollector):
    def collect(self) -> dict[str, str]:
        return {"hostname": socket.gethostname()}


class PythonModulesCollector(EnvironmentCollector):
    def collect(self) -> dict[str, str]:
        # Dump a comma separated string of loaded modules
        return {
            "python_modules": ",".join(list(sys.modules.keys())[:100])
        }  # limit to 100 for brevity in passport


class NDJSONExporter(TelemetryExporter):
    def __init__(self, stream: io.TextIOBase = sys.stdout):
        self.stream = stream

    def export(self, passport: KestPassport) -> None:
        data = passport.model_dump(mode="json")
        self.stream.write(json.dumps(data) + "\n")
        self.stream.flush()


class SQLiteExporter(TelemetryExporter):
    def __init__(
        self,
        db_path: str = "kest_telemetry.db",
        connection: Optional[sqlite3.Connection] = None,
    ):
        if connection:
            self.conn = connection
        else:
            self.conn = sqlite3.connect(db_path)

        self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS kest_passports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                passport_json TEXT
            )
            """
        )
        self.conn.commit()

    def export(self, passport: KestPassport) -> None:
        data = passport.model_dump(mode="json")
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO kest_passports (passport_json) VALUES (?)",
            (json.dumps(data),),
        )
        self.conn.commit()
