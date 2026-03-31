"""PentBoard database models and manager using SQLite."""

import sqlite3
import json
import os
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TargetStatus(str, Enum):
    NOT_STARTED = "not_started"
    RECON = "recon"
    SCANNING = "scanning"
    EXPLOITING = "exploiting"
    COMPROMISED = "compromised"
    COMPLETED = "completed"


class FindingStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Engagement:
    id: Optional[int] = None
    name: str = ""
    client: str = ""
    scope: str = ""
    start_date: str = ""
    end_date: str = ""
    status: str = "active"
    notes: str = ""
    created_at: str = ""


@dataclass
class Target:
    id: Optional[int] = None
    engagement_id: int = 0
    host: str = ""
    ip: str = ""
    hostname: str = ""
    os_guess: str = ""
    status: str = TargetStatus.NOT_STARTED.value
    ports: str = "[]"
    notes: str = ""
    created_at: str = ""

    @property
    def port_list(self) -> list:
        try:
            return json.loads(self.ports)
        except (json.JSONDecodeError, TypeError):
            return []

    @property
    def display_name(self) -> str:
        if self.hostname and self.ip:
            return f"{self.hostname} ({self.ip})"
        return self.hostname or self.ip or self.host


@dataclass
class Finding:
    id: Optional[int] = None
    engagement_id: int = 0
    target_id: Optional[int] = None
    title: str = ""
    severity: str = Severity.INFO.value
    status: str = FindingStatus.OPEN.value
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""
    cvss: str = ""
    tool_source: str = ""
    port: Optional[int] = None
    service: str = ""
    created_at: str = ""


class Database:
    """SQLite database manager for PentBoard."""

    def __init__(self, db_path: str = ""):
        if not db_path:
            data_dir = Path.home() / ".pentboard"
            data_dir.mkdir(exist_ok=True)
            db_path = str(data_dir / "pentboard.db")
        self.db_path = db_path
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                client TEXT DEFAULT '',
                scope TEXT DEFAULT '',
                start_date TEXT DEFAULT '',
                end_date TEXT DEFAULT '',
                status TEXT DEFAULT 'active',
                notes TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                host TEXT NOT NULL,
                ip TEXT DEFAULT '',
                hostname TEXT DEFAULT '',
                os_guess TEXT DEFAULT '',
                status TEXT DEFAULT 'not_started',
                ports TEXT DEFAULT '[]',
                notes TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                target_id INTEGER,
                title TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                status TEXT DEFAULT 'open',
                description TEXT DEFAULT '',
                evidence TEXT DEFAULT '',
                remediation TEXT DEFAULT '',
                cwe TEXT DEFAULT '',
                cvss TEXT DEFAULT '',
                tool_source TEXT DEFAULT '',
                port INTEGER,
                service TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE SET NULL
            );
        """)
        conn.commit()
        conn.close()

    # --- Engagement CRUD ---

    def create_engagement(self, name: str, client: str = "", scope: str = "",
                          start_date: str = "", end_date: str = "") -> int:
        conn = self._get_conn()
        cur = conn.execute(
            "INSERT INTO engagements (name, client, scope, start_date, end_date) VALUES (?, ?, ?, ?, ?)",
            (name, client, scope, start_date, end_date)
        )
        conn.commit()
        eid = cur.lastrowid
        conn.close()
        return eid

    def get_engagements(self) -> list[Engagement]:
        conn = self._get_conn()
        rows = conn.execute("SELECT * FROM engagements ORDER BY created_at DESC").fetchall()
        conn.close()
        return [Engagement(**dict(r)) for r in rows]

    def get_engagement(self, eid: int) -> Optional[Engagement]:
        conn = self._get_conn()
        row = conn.execute("SELECT * FROM engagements WHERE id = ?", (eid,)).fetchone()
        conn.close()
        return Engagement(**dict(row)) if row else None

    def delete_engagement(self, eid: int):
        conn = self._get_conn()
        conn.execute("DELETE FROM engagements WHERE id = ?", (eid,))
        conn.commit()
        conn.close()

    # --- Target CRUD ---

    def add_target(self, engagement_id: int, host: str, ip: str = "",
                   hostname: str = "", os_guess: str = "", ports: str = "[]") -> int:
        conn = self._get_conn()
        cur = conn.execute(
            "INSERT INTO targets (engagement_id, host, ip, hostname, os_guess, ports) VALUES (?, ?, ?, ?, ?, ?)",
            (engagement_id, host, ip, hostname, os_guess, ports)
        )
        conn.commit()
        tid = cur.lastrowid
        conn.close()
        return tid

    def get_targets(self, engagement_id: int) -> list[Target]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM targets WHERE engagement_id = ? ORDER BY created_at",
            (engagement_id,)
        ).fetchall()
        conn.close()
        return [Target(**dict(r)) for r in rows]

    def update_target_status(self, target_id: int, status: str):
        conn = self._get_conn()
        conn.execute("UPDATE targets SET status = ? WHERE id = ?", (status, target_id))
        conn.commit()
        conn.close()

    def update_target(self, target_id: int, **kwargs):
        conn = self._get_conn()
        sets = ", ".join(f"{k} = ?" for k in kwargs)
        vals = list(kwargs.values()) + [target_id]
        conn.execute(f"UPDATE targets SET {sets} WHERE id = ?", vals)
        conn.commit()
        conn.close()

    def delete_target(self, target_id: int):
        conn = self._get_conn()
        conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        conn.commit()
        conn.close()

    # --- Finding CRUD ---

    def add_finding(self, engagement_id: int, title: str, severity: str = "info",
                    target_id: int = None, description: str = "", evidence: str = "",
                    remediation: str = "", cwe: str = "", cvss: str = "",
                    tool_source: str = "", port: int = None, service: str = "") -> int:
        conn = self._get_conn()
        cur = conn.execute(
            """INSERT INTO findings
            (engagement_id, target_id, title, severity, description, evidence,
             remediation, cwe, cvss, tool_source, port, service)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (engagement_id, target_id, title, severity, description, evidence,
             remediation, cwe, cvss, tool_source, port, service)
        )
        conn.commit()
        fid = cur.lastrowid
        conn.close()
        return fid

    def get_findings(self, engagement_id: int) -> list[Finding]:
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM findings WHERE engagement_id = ? ORDER BY "
            "CASE severity "
            "  WHEN 'critical' THEN 0 "
            "  WHEN 'high' THEN 1 "
            "  WHEN 'medium' THEN 2 "
            "  WHEN 'low' THEN 3 "
            "  WHEN 'info' THEN 4 "
            "END, created_at DESC",
            (engagement_id,)
        ).fetchall()
        conn.close()
        return [Finding(**dict(r)) for r in rows]

    def update_finding_status(self, finding_id: int, status: str):
        conn = self._get_conn()
        conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
        conn.commit()
        conn.close()

    def delete_finding(self, finding_id: int):
        conn = self._get_conn()
        conn.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
        conn.commit()
        conn.close()

    # --- Stats ---

    def get_engagement_stats(self, engagement_id: int) -> dict:
        conn = self._get_conn()
        target_count = conn.execute(
            "SELECT COUNT(*) FROM targets WHERE engagement_id = ?", (engagement_id,)
        ).fetchone()[0]
        finding_counts = {}
        for sev in Severity:
            count = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE engagement_id = ? AND severity = ?",
                (engagement_id, sev.value)
            ).fetchone()[0]
            finding_counts[sev.value] = count
        total_findings = sum(finding_counts.values())
        compromised = conn.execute(
            "SELECT COUNT(*) FROM targets WHERE engagement_id = ? AND status = 'compromised'",
            (engagement_id,)
        ).fetchone()[0]
        conn.close()
        return {
            "targets": target_count,
            "compromised": compromised,
            "total_findings": total_findings,
            "findings_by_severity": finding_counts,
        }
