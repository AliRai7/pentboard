"""Shared test fixtures for PentBoard tests."""

import os
import tempfile
from pathlib import Path

import pytest

from pentboard.models.database import Database


@pytest.fixture
def db():
    """Create a temporary database for testing."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    database = Database(db_path=path)
    yield database
    os.unlink(path)


@pytest.fixture
def db_with_engagement(db):
    """Database with a pre-created engagement."""
    eid = db.create_engagement(
        name="Test Pentest",
        client="ACME Corp",
        scope="10.0.0.0/24, acme.com",
        start_date="2026-03-30",
        end_date="2026-04-15",
    )
    return db, eid


@pytest.fixture
def examples_dir():
    """Path to the examples directory."""
    return Path(__file__).parent.parent / "examples"


@pytest.fixture
def nmap_output(examples_dir):
    """Load example nmap output."""
    return (examples_dir / "nmap_basic.txt").read_text()


@pytest.fixture
def gobuster_output(examples_dir):
    """Load example gobuster output."""
    return (examples_dir / "gobuster_dir.txt").read_text()


@pytest.fixture
def nikto_output(examples_dir):
    """Load example nikto output."""
    return (examples_dir / "nikto_scan.txt").read_text()


@pytest.fixture
def masscan_output(examples_dir):
    """Load example masscan text output."""
    return (examples_dir / "masscan_output.txt").read_text()


@pytest.fixture
def ffuf_json(examples_dir):
    """Load example ffuf JSON output."""
    return (examples_dir / "ffuf_output.json").read_text()


@pytest.fixture
def ffuf_text(examples_dir):
    """Load example ffuf text output."""
    return (examples_dir / "ffuf_output.txt").read_text()


@pytest.fixture
def nuclei_jsonl(examples_dir):
    """Load example nuclei JSONL output."""
    return (examples_dir / "nuclei_output.jsonl").read_text()


@pytest.fixture
def nuclei_text(examples_dir):
    """Load example nuclei text output."""
    return (examples_dir / "nuclei_output.txt").read_text()


@pytest.fixture
def masscan_json(examples_dir):
    """Load example masscan JSON output."""
    return (examples_dir / "masscan_json.json").read_text()
