import io
import json
import sqlite3

from kest.core.models import KestPassport, PassportOrigin
from kest.presentation.defaults import (
    HostnameCollector,
    NDJSONExporter,
    PythonModulesCollector,
    SQLiteExporter,
)


def test_hostname_collector_pure():
    """Verify HostnameCollector retrieves machine hostname."""
    collector = HostnameCollector()
    env_data = collector.collect()
    assert "hostname" in env_data
    assert len(env_data["hostname"]) > 0


def test_python_modules_collector_pure():
    """Verify PythonModulesCollector retrieves active packages."""
    collector = PythonModulesCollector()
    env_data = collector.collect()
    assert "python_modules" in env_data
    assert len(env_data["python_modules"]) > 0


def test_ndjson_exporter_pure():
    """Verify NDJSONExporter serializes Passport to StringIO stream (avoids mock)."""
    stream = io.StringIO()
    exporter = NDJSONExporter(stream=stream)

    passport = KestPassport(
        origin=PassportOrigin(user_id="test_user", session_id="mem", policies={}),
        signature="",
        public_key_id="",
    )

    exporter.export(passport)

    content = stream.getvalue()
    assert content.strip().endswith("}")
    parsed = json.loads(content)
    assert parsed["origin"]["user_id"] == "test_user"


def test_sqlite_exporter_pure():
    """Verify SQLiteExporter pushes passport JSON to an in-memory DB (avoids mock)."""
    connection = sqlite3.connect(":memory:")
    exporter = SQLiteExporter(connection=connection)

    passport = KestPassport(
        origin=PassportOrigin(user_id="db_user", session_id="mem", policies={}),
        signature="",
        public_key_id="",
    )

    exporter.export(passport)

    # Query the memory DB back out
    cursor = connection.cursor()
    cursor.execute("SELECT passport_json FROM kest_passports LIMIT 1")
    row = cursor.fetchone()

    assert row is not None
    parsed = json.loads(row[0])
    assert parsed["origin"]["user_id"] == "db_user"
