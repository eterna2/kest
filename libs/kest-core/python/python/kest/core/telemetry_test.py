import json
import sqlite3

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

from kest.core.telemetry import FileSpanExporter, KestTelemetry, SQLiteSpanExporter


def test_file_span_exporter(tmp_path):
    filename = tmp_path / "test_audit.json"
    exporter = FileSpanExporter(filename=str(filename))

    # Create simple mock spans
    class MockSpan:
        def __init__(self, name):
            self.name = name

        def to_json(self):
            return {"name": self.name}

    spans = [MockSpan("span1"), MockSpan("span2")]

    # Initial export
    exporter.export(spans)
    assert filename.exists()

    with open(filename, "r") as f:
        data = json.load(f)
    assert len(data) == 2
    assert data[0]["name"] == "span1"

    # Subsequent export (append-like logic)
    spans2 = [MockSpan("span3")]
    exporter.export(spans2)

    with open(filename, "r") as f:
        data = json.load(f)
    assert len(data) == 3
    assert data[2]["name"] == "span3"


def test_file_span_exporter_invalid_json(tmp_path):
    filename = tmp_path / "corrupt.json"
    with open(filename, "w") as f:
        f.write("invalid json")

    exporter = FileSpanExporter(filename=str(filename))

    class MockSpan:
        def to_json(self):
            return {"name": "valid"}

    exporter.export([MockSpan()])

    with open(filename, "r") as f:
        data = json.load(f)
    assert len(data) == 1
    assert data[0]["name"] == "valid"


def test_sqlite_span_exporter(tmp_path):
    db_path = tmp_path / "test_audit.db"
    exporter = SQLiteSpanExporter(db_path=str(db_path))

    # Create mock span using SDK classes for high-fidelity testing
    resource = trace.get_tracer_provider().get_tracer(__name__)
    with resource.start_as_current_span("test_span"):
        # We need a ReadableSpan for the exporter, but start_as_current_span
        # returns an active span. The exporter usually gets finished spans.
        pass

    # The SQLite exporter expects certain attributes on the span
    # We will mock it to avoid complex OTel provider setup for a unit test
    class MockContext:
        def __init__(self):
            self.span_id = 0x123
            self.trace_id = 0xABC

    class HighFidelityMockSpan:
        def __init__(self):
            self.context = MockContext()
            self.name = "test_op"
            self.start_time = 1000
            self.end_time = 2000
            self.attributes = {"key": "value"}

    spans = [HighFidelityMockSpan()]
    exporter.export(spans)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM spans")
        row = cursor.fetchone()

    assert row is not None
    assert row[2] == "test_op"  # Name column
    assert json.loads(row[5])["key"] == "value"  # Attributes JSON


def test_kest_telemetry_setup(tmp_path):
    # Test file setup
    file_path = tmp_path / "kest_audit.json"
    provider = KestTelemetry.setup(
        "test_service", exporter_type="file", endpoint=str(file_path)
    )
    assert isinstance(provider, TracerProvider)
    assert provider.resource.attributes["service.name"] == "test_service"

    # Test sqlite setup
    db_path = tmp_path / "kest_audit.db"
    provider_sql = KestTelemetry.setup(
        "sql_service", exporter_type="sqlite", endpoint=str(db_path)
    )
    assert provider_sql.resource.attributes["service.name"] == "sql_service"

    # Test default/console
    KestTelemetry.setup("default_service")

    # Test shutdown by accessing the internal exporter if possible,
    # but since KestTelemetry.setup doesn't expose it easily,
    # we just test the exporter classes directly
    # provider.shutdown() is not correct, it should be provider.shutdown() anyway
    provider.shutdown()
    provider_sql.shutdown()


def test_otlp_exporter_setup(monkeypatch):
    # Mock OTLPSpanExporter to avoid gRPC dependencies in CI
    class MockOTLP:
        def __init__(self, endpoint=None):
            self.endpoint = endpoint

        def shutdown(self):
            pass

    monkeypatch.setattr("kest.core.telemetry.OTLPSpanExporter", MockOTLP)

    provider = KestTelemetry.setup(
        "otlp_service", exporter_type="otlp", endpoint="http://localhost:4317"
    )
    assert provider.resource.attributes["service.name"] == "otlp_service"
    provider.shutdown()


def test_file_span_exporter_shutdown():
    exporter = FileSpanExporter()
    exporter.shutdown()


def test_sqlite_span_exporter_shutdown():
    exporter = SQLiteSpanExporter(":memory:")
    exporter.shutdown()
