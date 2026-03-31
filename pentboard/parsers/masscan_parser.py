"""Parser for masscan output (text and JSON formats).

Masscan is a fast port scanner that outputs in several formats:
- Text: ``Discovered open port 80/tcp on 10.0.0.1``
- JSON (``-oJ``): Array of ``{"ip": ..., "ports": [...]}`` objects
- List (``-oL``): ``Host: 10.0.0.1 ()  Ports: 80/open/tcp//http//``

This parser handles text and JSON. Masscan does NOT do service detection,
so all services will be empty strings -- follow up with nmap ``-sV`` for
version info.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class MasscanPort:
    """A single open port discovered by masscan."""

    port: int
    protocol: str = "tcp"
    status: str = "open"
    reason: str = ""
    ttl: int = 0


@dataclass
class MasscanHost:
    """A host with one or more open ports."""

    ip: str = ""
    timestamp: str = ""
    ports: list[MasscanPort] = field(default_factory=list)


@dataclass
class MasscanResult:
    """Complete masscan scan result."""

    hosts: list[MasscanHost] = field(default_factory=list)
    scan_info: str = ""
    errors: list[str] = field(default_factory=list)


def _parse_masscan_text(output: str) -> MasscanResult:
    """Parse masscan text output line by line.

    Each line looks like:
        Discovered open port 80/tcp on 10.0.0.1
    We aggregate ports per host.
    """
    result = MasscanResult()
    host_map: dict[str, MasscanHost] = {}

    for line in output.splitlines():
        line = line.strip()

        # Scan info header
        if line.startswith("Starting masscan"):
            result.scan_info = line
            continue

        # Port discovery line
        port_match = re.match(
            r"Discovered open port (\d+)/(tcp|udp) on (\S+)", line
        )
        if port_match:
            port_num = int(port_match.group(1))
            proto = port_match.group(2)
            ip = port_match.group(3)

            if ip not in host_map:
                host_map[ip] = MasscanHost(ip=ip)

            host_map[ip].ports.append(
                MasscanPort(port=port_num, protocol=proto)
            )
            continue

        # List format: Host: 10.0.0.1 ()  Ports: 80/open/tcp//http//
        list_match = re.match(
            r"Host:\s+(\S+)\s+\(.*?\)\s+Ports:\s+(.+)", line
        )
        if list_match:
            ip = list_match.group(1)
            ports_str = list_match.group(2)

            if ip not in host_map:
                host_map[ip] = MasscanHost(ip=ip)

            for port_entry in ports_str.split(","):
                port_entry = port_entry.strip()
                parts = port_entry.split("/")
                if len(parts) >= 3:
                    try:
                        port_num = int(parts[0])
                    except ValueError:
                        continue
                    status = parts[1] if len(parts) > 1 else "open"
                    proto = parts[2] if len(parts) > 2 else "tcp"
                    host_map[ip].ports.append(
                        MasscanPort(
                            port=port_num,
                            protocol=proto,
                            status=status,
                        )
                    )

    # Sort ports within each host and collect
    for host in host_map.values():
        host.ports.sort(key=lambda p: p.port)
        result.hosts.append(host)

    # Sort hosts by IP for deterministic output
    result.hosts.sort(key=lambda h: h.ip)
    return result


def _parse_masscan_json(content: str) -> MasscanResult:
    """Parse masscan JSON (``-oJ``) output.

    Masscan JSON is an array of objects, each with one IP and a ``ports``
    list.  Multiple entries can share the same IP, so we merge them.
    """
    result = MasscanResult()
    host_map: dict[str, MasscanHost] = {}

    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        result.errors.append(f"JSON parse error: {exc}")
        return result

    if not isinstance(data, list):
        result.errors.append("Expected JSON array at top level")
        return result

    for entry in data:
        if not isinstance(entry, dict):
            continue

        ip = entry.get("ip", "")
        if not ip:
            continue

        if ip not in host_map:
            host_map[ip] = MasscanHost(
                ip=ip,
                timestamp=str(entry.get("timestamp", "")),
            )

        for port_data in entry.get("ports", []):
            if not isinstance(port_data, dict):
                continue
            try:
                port_num = int(port_data.get("port", 0))
            except (ValueError, TypeError):
                continue
            if port_num == 0:
                continue

            host_map[ip].ports.append(
                MasscanPort(
                    port=port_num,
                    protocol=str(port_data.get("proto", "tcp")),
                    status=str(port_data.get("status", "open")),
                    reason=str(port_data.get("reason", "")),
                    ttl=int(port_data.get("ttl", 0)),
                )
            )

    for host in host_map.values():
        host.ports.sort(key=lambda p: p.port)
        result.hosts.append(host)

    result.hosts.sort(key=lambda h: h.ip)
    return result


def parse_masscan(content: str) -> MasscanResult:
    """Auto-detect format and parse masscan output.

    Tries JSON first (starts with ``[``), falls back to text parsing.
    """
    content = content.strip()
    if not content:
        return MasscanResult()

    if content.startswith("[") or content.startswith("{"):
        return _parse_masscan_json(content)

    return _parse_masscan_text(content)
