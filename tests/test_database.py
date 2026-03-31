"""Tests for PentBoard database operations."""

import json
import pytest
from pentboard.models.database import Database, Severity, TargetStatus


class TestEngagements:
    def test_create_engagement(self, db):
        eid = db.create_engagement("Test", client="Client", scope="10.0.0.0/24")
        assert eid > 0

    def test_get_engagements(self, db):
        db.create_engagement("Eng1")
        db.create_engagement("Eng2")
        engs = db.get_engagements()
        assert len(engs) == 2

    def test_get_engagement_by_id(self, db):
        eid = db.create_engagement("Test", client="ACME")
        eng = db.get_engagement(eid)
        assert eng is not None
        assert eng.name == "Test"
        assert eng.client == "ACME"

    def test_get_nonexistent_engagement(self, db):
        eng = db.get_engagement(9999)
        assert eng is None

    def test_delete_engagement(self, db):
        eid = db.create_engagement("ToDelete")
        db.delete_engagement(eid)
        assert db.get_engagement(eid) is None


class TestTargets:
    def test_add_target(self, db_with_engagement):
        db, eid = db_with_engagement
        tid = db.add_target(eid, "10.0.0.1", ip="10.0.0.1", hostname="web01")
        assert tid > 0

    def test_get_targets(self, db_with_engagement):
        db, eid = db_with_engagement
        db.add_target(eid, "10.0.0.1", ip="10.0.0.1")
        db.add_target(eid, "10.0.0.2", ip="10.0.0.2")
        targets = db.get_targets(eid)
        assert len(targets) == 2

    def test_update_target_status(self, db_with_engagement):
        db, eid = db_with_engagement
        tid = db.add_target(eid, "10.0.0.1", ip="10.0.0.1")
        db.update_target_status(tid, TargetStatus.COMPROMISED.value)
        targets = db.get_targets(eid)
        assert targets[0].status == "compromised"

    def test_target_with_ports(self, db_with_engagement):
        db, eid = db_with_engagement
        ports = json.dumps([22, 80, 443])
        tid = db.add_target(eid, "10.0.0.1", ip="10.0.0.1", ports=ports)
        targets = db.get_targets(eid)
        assert targets[0].port_list == [22, 80, 443]

    def test_delete_target(self, db_with_engagement):
        db, eid = db_with_engagement
        tid = db.add_target(eid, "10.0.0.1", ip="10.0.0.1")
        db.delete_target(tid)
        assert len(db.get_targets(eid)) == 0

    def test_cascade_delete(self, db_with_engagement):
        db, eid = db_with_engagement
        db.add_target(eid, "10.0.0.1", ip="10.0.0.1")
        db.delete_engagement(eid)
        assert len(db.get_targets(eid)) == 0


class TestFindings:
    def test_add_finding(self, db_with_engagement):
        db, eid = db_with_engagement
        fid = db.add_finding(eid, "SQLi in login", severity="critical")
        assert fid > 0

    def test_findings_sorted_by_severity(self, db_with_engagement):
        db, eid = db_with_engagement
        db.add_finding(eid, "Info finding", severity="info")
        db.add_finding(eid, "Critical finding", severity="critical")
        db.add_finding(eid, "Medium finding", severity="medium")
        findings = db.get_findings(eid)
        assert findings[0].severity == "critical"
        assert findings[1].severity == "medium"
        assert findings[2].severity == "info"

    def test_finding_with_all_fields(self, db_with_engagement):
        db, eid = db_with_engagement
        tid = db.add_target(eid, "10.0.0.1", ip="10.0.0.1")
        fid = db.add_finding(
            eid,
            title="SQL Injection",
            severity="critical",
            target_id=tid,
            description="Union-based SQLi in search param",
            evidence="GET /search?q=1' UNION SELECT--",
            remediation="Use parameterized queries",
            cwe="CWE-89",
            cvss="9.8",
            tool_source="sqlmap",
            port=80,
            service="http",
        )
        findings = db.get_findings(eid)
        f = findings[0]
        assert f.title == "SQL Injection"
        assert f.cwe == "CWE-89"
        assert f.port == 80

    def test_update_finding_status(self, db_with_engagement):
        db, eid = db_with_engagement
        fid = db.add_finding(eid, "Test", severity="info")
        db.update_finding_status(fid, "confirmed")
        findings = db.get_findings(eid)
        assert findings[0].status == "confirmed"


class TestStats:
    def test_engagement_stats(self, db_with_engagement):
        db, eid = db_with_engagement
        db.add_target(eid, "10.0.0.1", ip="10.0.0.1")
        tid = db.add_target(eid, "10.0.0.2", ip="10.0.0.2")
        db.update_target_status(tid, "compromised")
        db.add_finding(eid, "Crit", severity="critical")
        db.add_finding(eid, "High", severity="high")
        db.add_finding(eid, "Info", severity="info")

        stats = db.get_engagement_stats(eid)
        assert stats["targets"] == 2
        assert stats["compromised"] == 1
        assert stats["total_findings"] == 3
        assert stats["findings_by_severity"]["critical"] == 1
        assert stats["findings_by_severity"]["high"] == 1
