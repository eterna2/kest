import json
import os
import sqlite3
from typing import Optional

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SpanExporter,
)


class FileSpanExporter(SpanExporter):
    """
    OpenTelemetry SpanExporter that persists spans to a JSON file.

    Useful for local development and auditing where a full OTLP collector
    is not available.
    """

    def __init__(self, filename="kest_audit.json"):
        """
        Initializes the file exporter.

        Args:
            filename: Path to the JSON file where spans will be stored.
        """
        self.filename = filename

    def export(self, spans):
        """
        Exports a batch of spans to the JSON file.

        Appends to existing data if the file exists.
        """
        data = []
        if os.path.exists(self.filename):
            try:
                with open(self.filename, "r") as f:
                    content = f.read()
                    if content:
                        data = json.loads(content)
            except Exception:
                pass

        for span in spans:
            data.append(span.to_json())

        with open(self.filename, "w") as f:
            json.dump(data, f, indent=2)

        return True

    def shutdown(self):
        """No-op shutdown."""
        pass


class SQLiteSpanExporter(SpanExporter):
    """
    OpenTelemetry SpanExporter that persists spans to a SQLite database.

    Provides a structured audit log that can be queried easily for
    compliance and security analysis.
    """

    def __init__(self, db_path="kest_audit.db"):
        """
        Initializes the SQLite exporter and creates the schema if needed.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Creates the 'spans' table if it doesn't already exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS spans (
                    id TEXT PRIMARY KEY,
                    trace_id TEXT,
                    name TEXT,
                    start_time INTEGER,
                    end_time INTEGER,
                    attributes TEXT
                )
            """)

    def export(self, spans):
        """Inserts a batch of spans into the SQLite database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO spans (id, trace_id, name, start_time, end_time, attributes) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    (
                        str(span.context.span_id),
                        str(span.context.trace_id),
                        span.name,
                        span.start_time,
                        span.end_time,
                        json.dumps(dict(span.attributes) if span.attributes else {}),
                    )
                    for span in spans
                ),
            )
        return True

    def shutdown(self):
        """No-op shutdown."""
        pass


class KestTelemetry:
    """
    Helper for setting up OpenTelemetry for Kest-verified applications.
    """

    @staticmethod
    def setup(
        service_name: str,
        exporter_type: str = "console",
        endpoint: Optional[str] = None,
    ) -> TracerProvider:
        """
        Configures the global TracerProvider with the specified exporter.

        Args:
            service_name: The name of the service for OTel resources.
            exporter_type: One of 'console', 'otlp', 'file', or 'sqlite'.
            endpoint: The endpoint or filename for the exporter (e.g., OTLP URL,
                file path).

        Returns:
            TracerProvider: The configured OTel TracerProvider.
        """
        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)

        exporter: SpanExporter

        if exporter_type == "otlp":
            exporter = OTLPSpanExporter(endpoint=endpoint)
        elif exporter_type == "file":
            exporter = FileSpanExporter(filename=endpoint or "kest_audit.json")
        elif exporter_type == "sqlite":
            exporter = SQLiteSpanExporter(db_path=endpoint or "kest_audit.db")
        else:
            exporter = ConsoleSpanExporter()

        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        return provider
