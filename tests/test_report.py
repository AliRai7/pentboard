"""Tests for PentBoard report generation."""

import json
import pytest
from pentboard.utils.report import generate_report


class TestReportGeneration:
    def test_generate_empty_report(self, db_with_engagement):
        db, eid = db_with_engagement
        report = generate_report(db, eid)
        assert "# Penetration Test Report" in report
        assert "ACME Corp" in report
        assert "0** finding" in report

    def test_generate_report_with_findings(self, db_with_engagement):
        db, eid = db_with_engagement
        tid = db.add_target(eid, "10.0.0.1", ip="10.0.0.1", hostname="web01")
        db.add_finding(
            eid, "SQL Injection", severity="critical",
            target_id=tid, description="Union-based SQLi",
            cwe="CWE-89", cvss="9.8", tool_source="sqlmap",
            port=80, service="http",
        )
        report = generate_report(db, eid)
        assert "SQL Injection" in report
        assert "CWE-89" in report
        assert "critical" in report.lower()

    def test_report_severity_order(self, db_with_engagement):
        db, eid = db_with_engagement
        db.add_finding(eid, "Info Thing", severity="info")
        db.add_finding(eid, "Critical Thing", severity="critical")
        report = generate_report(db, eid)
        crit_pos = report.index("Critical Thing")
        info_pos = report.index("Info Thing")
        assert crit_pos < info_pos

    def test_report_with_targets(self, db_with_engagement):
        db, eid = db_with_engagement
        db.add_target(eid, "10.0.0.1", ip="10.0.0.1",
                       hostname="web01", os_guess="Ubuntu 22.04",
                       ports=json.dumps([22, 80, 443]))
        report = generate_report(db, eid)
        assert "web01" in report
        assert "10.0.0.1" in report
        assert "22" in report

    def test_nonexistent_engagement(self, db):
        report = generate_report(db, 9999)
        assert "Error" in report

    def test_report_contains_pentboard_credit(self, db_with_engagement):
        db, eid = db_with_engagement
        report = generate_report(db, eid)
        assert "PentBoard" in report
