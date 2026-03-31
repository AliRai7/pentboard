"""Parser for nuclei vulnerability scanner output (JSONL and text formats).

nuclei outputs in two primary modes:
- JSONL (default with ``-jsonl`` or ``-json``): One JSON object per line,
  each containing template info, severity, matched URL, and host.
- Text (terminal output): ``[timestamp] [template-id] [protocol] [severity] matched-url``

The key advantage of nuclei is that severity is built into the template,
so we can trust it directly without needing to auto-classify.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NucleiClassification:
    """CVE/CWE/CVSS classification from the template."""

    cve_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    cvss_score: float = 0.0
    cvss_metrics: str = ""


@dataclass
class NucleiInfo:
    """Template metadata from the info block."""

    name: str = ""
    author: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    description: str = ""
    severity: str = "info"
    classification: NucleiClassification = field(
        default_factory=NucleiClassification
    )
    reference: list[str] = field(default_factory=list)


@dataclass
class NucleiFinding:
    """A single nuclei finding."""

    template_id: str = ""
    info: NucleiInfo = field(default_factory=NucleiInfo)
    scan_type: str = ""
    host: str = ""
    matched_at: str = ""
    ip: str = ""
    timestamp: str = ""


@dataclass
class NucleiResult:
    """Complete nuclei scan result."""

    findings: list[NucleiFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _parse_classification(data: dict) -> NucleiClassification:
    """Parse the classification sub-object from a JSON entry."""
    if not isinstance(data, dict):
        return NucleiClassification()

    cve_ids = data.get("cve-id", [])
    if isinstance(cve_ids, str):
        cve_ids = [cve_ids]

    cwe_ids = data.get("cwe-id", [])
    if isinstance(cwe_ids, str):
        cwe_ids = [cwe_ids]

    try:
        cvss_score = float(data.get("cvss-score", 0.0))
    except (ValueError, TypeError):
        cvss_score = 0.0

    return NucleiClassification(
        cve_ids=cve_ids if isinstance(cve_ids, list) else [],
        cwe_ids=cwe_ids if isinstance(cwe_ids, list) else [],
        cvss_score=cvss_score,
        cvss_metrics=str(data.get("cvss-metrics", "")),
    )


def _parse_nuclei_jsonl(content: str) -> NucleiResult:
    """Parse nuclei JSONL output (one JSON object per line).

    Each line is a complete JSON object with template-id, info, host,
    matched-at, ip, and timestamp fields.
    """
    result = NucleiResult()

    for line_num, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or not line.startswith("{"):
            continue

        try:
            data = json.loads(line)
        except json.JSONDecodeError as exc:
            result.errors.append(f"Line {line_num}: JSON parse error: {exc}")
            continue

        if not isinstance(data, dict):
            continue

        # Parse info block
        info_data = data.get("info", {})
        if not isinstance(info_data, dict):
            info_data = {}

        classification = _parse_classification(
            info_data.get("classification", {})
        )

        author = info_data.get("author", [])
        if isinstance(author, str):
            author = [author]

        tags = info_data.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        reference = info_data.get("reference", [])
        if isinstance(reference, str):
            reference = [reference]

        info = NucleiInfo(
            name=str(info_data.get("name", "")),
            author=author if isinstance(author, list) else [],
            tags=tags if isinstance(tags, list) else [],
            description=str(info_data.get("description", "")),
            severity=str(info_data.get("severity", "info")).lower(),
            classification=classification,
            reference=reference if isinstance(reference, list) else [],
        )

        finding = NucleiFinding(
            template_id=str(data.get("template-id", "")),
            info=info,
            scan_type=str(data.get("type", "")),
            host=str(data.get("host", "")),
            matched_at=str(data.get("matched-at", "")),
            ip=str(data.get("ip", "")),
            timestamp=str(data.get("timestamp", "")),
        )
        result.findings.append(finding)

    return result


def _parse_nuclei_text(output: str) -> NucleiResult:
    """Parse nuclei terminal text output.

    Lines look like::

        [2026-03-30 10:30:00] [cve-2021-44228] [http] [critical] http://10.0.0.5:8443/
    """
    result = NucleiResult()

    for line in output.splitlines():
        line = line.strip()

        # Match: [timestamp] [template-id] [protocol] [severity] matched-url
        match = re.match(
            r"\[([^\]]+)\]\s+"        # timestamp
            r"\[([^\]]+)\]\s+"        # template-id
            r"\[([^\]]+)\]\s+"        # protocol/type
            r"\[([^\]]+)\]\s+"        # severity
            r"(\S+)",                 # matched URL/host
            line,
        )
        if not match:
            continue

        timestamp = match.group(1)
        template_id = match.group(2)
        scan_type = match.group(3)
        severity = match.group(4).lower()
        matched_at = match.group(5)

        # Extract IP from matched URL
        ip = ""
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", matched_at)
        if ip_match:
            ip = ip_match.group(1)

        # Extract port from matched URL
        port_match = re.search(r":(\d+)", matched_at)

        info = NucleiInfo(
            name=template_id,
            severity=severity,
        )

        finding = NucleiFinding(
            template_id=template_id,
            info=info,
            scan_type=scan_type,
            host=matched_at,
            matched_at=matched_at,
            ip=ip,
            timestamp=timestamp,
        )
        result.findings.append(finding)

    return result


def parse_nuclei(content: str) -> NucleiResult:
    """Auto-detect format and parse nuclei output.

    If the first non-empty line starts with ``{``, treat as JSONL.
    Otherwise, parse as text output.
    """
    content = content.strip()
    if not content:
        return NucleiResult()

    # Find first non-empty line to determine format
    for line in content.splitlines():
        line = line.strip()
        if line:
            if line.startswith("{"):
                return _parse_nuclei_jsonl(content)
            break

    return _parse_nuclei_text(content)
