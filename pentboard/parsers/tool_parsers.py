"""Parsers for gobuster, nikto, and other common pentest tool output."""

import re
from dataclasses import dataclass, field


@dataclass
class GobusterResult:
    url: str = ""
    status: int = 0
    size: int = 0
    redirect: str = ""


@dataclass
class GobusterOutput:
    target: str = ""
    results: list[GobusterResult] = field(default_factory=list)
    mode: str = "dir"


def parse_gobuster(output: str) -> GobusterOutput:
    """Parse gobuster dir/vhost/dns output."""
    result = GobusterOutput()

    for line in output.splitlines():
        line = line.strip()

        # Target URL
        url_match = re.match(r"\[.\]\s+Url:\s+(.+)", line)
        if url_match:
            result.target = url_match.group(1).strip()
            continue

        # Mode
        mode_match = re.match(r"\[.\]\s+Mode:\s+(.+)", line)
        if mode_match:
            result.mode = mode_match.group(1).strip().lower()
            continue

        # Dir mode: /path (Status: 200) [Size: 1234]
        dir_match = re.match(
            r"(/\S*)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\](?:\s+\[--> (.+)\])?",
            line
        )
        if dir_match:
            entry = GobusterResult(
                url=dir_match.group(1),
                status=int(dir_match.group(2)),
                size=int(dir_match.group(3)),
                redirect=dir_match.group(4) or "",
            )
            result.results.append(entry)
            continue

        # Also match: Found: hostname (Status: 200) [Size: 1234]
        found_match = re.match(
            r"Found:\s+(\S+)\s+(?:Status:\s+(\d+))?\s*(?:\[Size:\s+(\d+)\])?",
            line
        )
        if found_match:
            entry = GobusterResult(
                url=found_match.group(1),
                status=int(found_match.group(2) or 0),
                size=int(found_match.group(3) or 0),
            )
            result.results.append(entry)

    return result


@dataclass
class NiktoFinding:
    id: str = ""
    method: str = ""
    url: str = ""
    description: str = ""
    osvdb: str = ""


@dataclass
class NiktoOutput:
    target: str = ""
    ip: str = ""
    port: int = 0
    findings: list[NiktoFinding] = field(default_factory=list)


def parse_nikto(output: str) -> NiktoOutput:
    """Parse nikto scan output."""
    result = NiktoOutput()

    for line in output.splitlines():
        line = line.strip()

        # Target
        target_match = re.match(r"\+\s+Target IP:\s+(.+)", line)
        if target_match:
            result.ip = target_match.group(1).strip()
            continue

        target_host_match = re.match(r"\+\s+Target Hostname:\s+(.+)", line)
        if target_host_match:
            result.target = target_host_match.group(1).strip()
            continue

        port_match = re.match(r"\+\s+Target Port:\s+(\d+)", line)
        if port_match:
            result.port = int(port_match.group(1))
            continue

        # Findings: + OSVDB-XXX: /path: Description
        finding_match = re.match(
            r"\+\s+(?:(OSVDB-\d+):\s+)?(/\S*):\s+(.+)", line
        )
        if finding_match:
            f = NiktoFinding(
                osvdb=finding_match.group(1) or "",
                url=finding_match.group(2),
                description=finding_match.group(3).strip(),
            )
            result.findings.append(f)
            continue

        # Generic finding without path
        generic_match = re.match(r"\+\s+(?:(OSVDB-\d+):\s+)?(.+)", line)
        if generic_match and not line.startswith("+ Target") and not line.startswith("+ Start") and not line.startswith("+ End"):
            desc = generic_match.group(2).strip()
            if desc and not desc.startswith("---") and len(desc) > 10:
                f = NiktoFinding(
                    osvdb=generic_match.group(1) or "",
                    description=desc,
                )
                result.findings.append(f)

    return result


def detect_tool(content: str) -> str:
    """Auto-detect which tool generated the output.

    Detection order matters -- more specific signatures first.
    """
    content_lower = content.lower()

    # Nmap
    if "nmap scan report" in content_lower or "<nmaprun" in content_lower:
        return "nmap"

    # Masscan (text or JSON with masscan markers)
    if "masscan" in content_lower or "discovered open port" in content_lower:
        return "masscan"

    # Nuclei (JSONL with template-id, or text with [id] [proto] [severity] pattern)
    if "nuclei" in content_lower or "template-id" in content_lower:
        return "nuclei"
    # Nuclei text format: [timestamp] [template] [proto] [critical|high|medium|low|info] url
    import re
    if re.search(
        r"\[.+?\]\s+\[.+?\]\s+\[(?:http|network|dns|ssl|tcp|udp)\]\s+"
        r"\[(?:critical|high|medium|low|info)\]",
        content_lower,
    ):
        return "nuclei"

    # ffuf (JSON with "results" key or text with ffuf banner/markers)
    if "ffuf" in content_lower or (
        '"results"' in content and '"status"' in content and '"length"' in content
    ):
        return "ffuf"

    # Gobuster
    if "gobuster" in content_lower or "(status:" in content_lower:
        return "gobuster"

    # Nikto
    if "nikto" in content_lower and "+ target" in content_lower:
        return "nikto"

    return "unknown"
