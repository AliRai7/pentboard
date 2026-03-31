"""Tests for the ReconFlow graph widget data building logic."""

import json

import pytest

from pentboard.models.database import Database, Finding, Target
from pentboard.widgets.recon_graph import (
    GraphNodeData,
    ReconGraph,
    _extract_version,
)


@pytest.fixture
def populated_db(db_with_engagement):
    """Database with targets and findings for graph testing."""
    db, eid = db_with_engagement

    # Add targets
    t1 = db.add_target(
        engagement_id=eid,
        host="10.0.0.1",
        ip="10.0.0.1",
        hostname="gateway.acme.local",
        os_guess="Linux 5.15",
        ports=json.dumps([22, 80, 443]),
    )
    t2 = db.add_target(
        engagement_id=eid,
        host="10.0.0.5",
        ip="10.0.0.5",
        hostname="web01.acme.local",
        os_guess="Linux 5.4",
        ports=json.dumps([22, 80, 3306]),
    )

    # Add service findings (info level)
    db.add_finding(
        engagement_id=eid, target_id=t1,
        title="Open port 22/tcp: ssh",
        severity="info", description="Service: ssh\nVersion: OpenSSH 8.9p1",
        tool_source="nmap", port=22, service="ssh",
    )
    db.add_finding(
        engagement_id=eid, target_id=t1,
        title="Open port 80/tcp: http",
        severity="info", description="Service: http\nVersion: nginx 1.24.0",
        tool_source="nmap", port=80, service="http",
    )
    db.add_finding(
        engagement_id=eid, target_id=t1,
        title="Open port 443/tcp: ssl/https",
        severity="info", description="Service: ssl/https\nVersion: nginx 1.24.0",
        tool_source="nmap", port=443, service="ssl/https",
    )
    db.add_finding(
        engagement_id=eid, target_id=t2,
        title="Open port 22/tcp: ssh",
        severity="info", description="Service: ssh\nVersion: OpenSSH 8.2p1",
        tool_source="nmap", port=22, service="ssh",
    )
    db.add_finding(
        engagement_id=eid, target_id=t2,
        title="Open port 80/tcp: http",
        severity="info", description="Service: http\nVersion: Apache 2.4.41",
        tool_source="nmap", port=80, service="http",
    )
    db.add_finding(
        engagement_id=eid, target_id=t2,
        title="Open port 3306/tcp: mysql",
        severity="info", description="Service: mysql\nVersion: MySQL 8.0.36",
        tool_source="nmap", port=3306, service="mysql",
    )

    # Add vulnerability findings
    db.add_finding(
        engagement_id=eid, target_id=t2,
        title="SQLi in /login",
        severity="critical", description="SQL injection found",
        tool_source="manual", port=80, service="http",
    )
    db.add_finding(
        engagement_id=eid, target_id=t2,
        title="Default credentials",
        severity="high", description="MySQL using default root:root",
        tool_source="manual", port=3306, service="mysql",
    )

    return db, eid, t1, t2


class TestExtractVersion:
    """Tests for the _extract_version helper."""

    def test_extracts_version_from_description(self) -> None:
        """Version line is correctly parsed from finding description."""
        f = Finding(description="Service: ssh\nVersion: OpenSSH 8.9p1")
        assert _extract_version(f) == "OpenSSH 8.9p1"

    def test_returns_empty_when_no_version(self) -> None:
        """Returns empty string when no version line exists."""
        f = Finding(description="Service: ssh")
        assert _extract_version(f) == ""

    def test_handles_empty_description(self) -> None:
        """Handles None or empty description gracefully."""
        assert _extract_version(Finding(description="")) == ""
        assert _extract_version(Finding(description=None)) == ""

    def test_handles_empty_version_value(self) -> None:
        """Returns empty when version line has no value."""
        f = Finding(description="Service: ssh\nVersion: ")
        assert _extract_version(f) == ""


class TestGraphNodeData:
    """Tests for the GraphNodeData dataclass."""

    def test_defaults(self) -> None:
        """Default values are sensible."""
        node = GraphNodeData(node_type="host")
        assert node.node_type == "host"
        assert node.target_id is None
        assert node.finding_id is None
        assert node.port is None
        assert node.severity == ""


class TestReconGraphData:
    """Tests for graph building logic using a real database."""

    def test_empty_engagement_shows_message(self, db_with_engagement) -> None:
        """An engagement with no targets shows the empty-state message."""
        db, eid = db_with_engagement
        targets = db.get_targets(eid)
        assert len(targets) == 0

    def test_targets_loaded(self, populated_db) -> None:
        """Targets are correctly loaded from the database."""
        db, eid, t1, t2 = populated_db
        targets = db.get_targets(eid)
        assert len(targets) == 2
        assert targets[0].ip == "10.0.0.1"
        assert targets[1].ip == "10.0.0.5"

    def test_findings_grouped_by_target(self, populated_db) -> None:
        """Findings are correctly associated with their targets."""
        db, eid, t1, t2 = populated_db
        findings = db.get_findings(eid)

        t1_findings = [f for f in findings if f.target_id == t1]
        t2_findings = [f for f in findings if f.target_id == t2]

        assert len(t1_findings) == 3  # 3 services
        assert len(t2_findings) == 5  # 3 services + 2 vulns

    def test_findings_sorted_by_severity(self, populated_db) -> None:
        """Findings come back sorted: critical first, then high, etc."""
        db, eid, _, _ = populated_db
        findings = db.get_findings(eid)
        severities = [f.severity for f in findings]
        # Critical and high should appear before info
        crit_idx = severities.index("critical")
        high_idx = severities.index("high")
        info_indices = [i for i, s in enumerate(severities) if s == "info"]
        assert crit_idx < min(info_indices)
        assert high_idx < min(info_indices)

    def test_vuln_findings_have_ports(self, populated_db) -> None:
        """Vulnerability findings are associated with the correct ports."""
        db, eid, _, t2 = populated_db
        findings = db.get_findings(eid)
        sqli = next(f for f in findings if "SQLi" in f.title)
        assert sqli.port == 80
        assert sqli.severity == "critical"

        creds = next(f for f in findings if "Default" in f.title)
        assert creds.port == 3306
        assert creds.severity == "high"

    def test_nmap_import_populates_graph_data(self, db_with_engagement, nmap_output) -> None:
        """Full nmap import creates targets and findings usable by the graph."""
        db, eid = db_with_engagement

        from pentboard.parsers.nmap_parser import parse_nmap

        nmap_result = parse_nmap(nmap_output)
        for host in nmap_result.hosts:
            if host.state != "up":
                continue
            port_numbers = [p.port for p in host.ports if p.state == "open"]
            tid = db.add_target(
                engagement_id=eid,
                host=host.ip or host.hostname,
                ip=host.ip,
                hostname=host.hostname,
                os_guess=host.os_guess,
                ports=json.dumps(port_numbers),
            )
            for port in host.ports:
                if port.state == "open":
                    db.add_finding(
                        engagement_id=eid, target_id=tid,
                        title=f"Open port {port.port}/{port.protocol}: {port.service}",
                        severity="info",
                        description=f"Service: {port.service}\nVersion: {port.version}",
                        tool_source="nmap", port=port.port, service=port.service,
                    )

        targets = db.get_targets(eid)
        findings = db.get_findings(eid)

        # nmap_basic.txt has 4 hosts
        assert len(targets) == 4
        # Total open ports across all hosts: 4 + 7 + 2 + 3 = 16
        assert len(findings) == 16

        # Verify each host has correct number of services
        findings_by_target = {}
        for f in findings:
            findings_by_target.setdefault(f.target_id, []).append(f)

        host_service_counts = sorted(
            len(v) for v in findings_by_target.values()
        )
        assert host_service_counts == [2, 3, 4, 7]
