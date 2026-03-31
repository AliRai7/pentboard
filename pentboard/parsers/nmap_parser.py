"""Parser for Nmap scan output (normal and XML formats)."""

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NmapPort:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = ""
    version: str = ""
    extra_info: str = ""


@dataclass
class NmapHost:
    ip: str = ""
    hostname: str = ""
    state: str = "up"
    os_guess: str = ""
    ports: list[NmapPort] = field(default_factory=list)
    mac: str = ""


@dataclass
class NmapResult:
    hosts: list[NmapHost] = field(default_factory=list)
    scan_info: str = ""
    errors: list[str] = field(default_factory=list)


def parse_nmap_normal(output: str) -> NmapResult:
    """Parse nmap normal (-oN) text output."""
    result = NmapResult()
    current_host = None

    for line in output.splitlines():
        line = line.strip()

        # Scan report header
        report_match = re.match(
            r"Nmap scan report for\s+(?:(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)|(\d+\.\d+\.\d+\.\d+))",
            line
        )
        if report_match:
            if current_host:
                result.hosts.append(current_host)
            current_host = NmapHost()
            if report_match.group(1):
                current_host.hostname = report_match.group(1)
                current_host.ip = report_match.group(2)
            else:
                current_host.ip = report_match.group(3)
            continue

        # Also match simpler format
        simple_report = re.match(r"Nmap scan report for\s+(\S+)", line)
        if simple_report and not report_match:
            if current_host:
                result.hosts.append(current_host)
            current_host = NmapHost()
            host_str = simple_report.group(1)
            if re.match(r"\d+\.\d+\.\d+\.\d+", host_str):
                current_host.ip = host_str
            else:
                current_host.hostname = host_str
            continue

        # Host status
        if line.startswith("Host is"):
            state_match = re.match(r"Host is (\w+)", line)
            if state_match and current_host:
                current_host.state = state_match.group(1)
            continue

        # Port lines: 80/tcp open http Apache httpd 2.4.41
        port_match = re.match(
            r"(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)?\s*(.*)?",
            line
        )
        if port_match and current_host:
            port = NmapPort(
                port=int(port_match.group(1)),
                protocol=port_match.group(2),
                state=port_match.group(3),
                service=port_match.group(4) or "",
                version=(port_match.group(5) or "").strip(),
            )
            current_host.ports.append(port)
            continue

        # MAC address
        mac_match = re.match(r"MAC Address:\s+(\S+)", line)
        if mac_match and current_host:
            current_host.mac = mac_match.group(1)
            continue

        # OS detection
        os_match = re.match(r"(?:OS details|Running):\s+(.+)", line)
        if os_match and current_host:
            current_host.os_guess = os_match.group(1).strip()
            continue

        # Aggressive OS guesses
        os_guess_match = re.match(r"Aggressive OS guesses:\s+(.+)", line)
        if os_guess_match and current_host:
            current_host.os_guess = os_guess_match.group(1).split(",")[0].strip()
            continue

    if current_host:
        result.hosts.append(current_host)

    return result


def parse_nmap_xml(xml_content: str) -> NmapResult:
    """Parse nmap XML (-oX) output."""
    result = NmapResult()

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as e:
        result.errors.append(f"XML parse error: {e}")
        return result

    for host_elem in root.findall(".//host"):
        host = NmapHost()

        # Status
        status = host_elem.find("status")
        if status is not None:
            host.state = status.get("state", "unknown")

        # Address
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                host.ip = addr.get("addr", "")
            elif addr.get("addrtype") == "mac":
                host.mac = addr.get("addr", "")

        # Hostnames
        hostname_elem = host_elem.find(".//hostname")
        if hostname_elem is not None:
            host.hostname = hostname_elem.get("name", "")

        # Ports
        for port_elem in host_elem.findall(".//port"):
            state_elem = port_elem.find("state")
            service_elem = port_elem.find("service")
            port = NmapPort(
                port=int(port_elem.get("portid", 0)),
                protocol=port_elem.get("protocol", "tcp"),
                state=state_elem.get("state", "") if state_elem is not None else "",
                service=service_elem.get("name", "") if service_elem is not None else "",
                version=service_elem.get("product", "") if service_elem is not None else "",
                extra_info=service_elem.get("extrainfo", "") if service_elem is not None else "",
            )
            if service_elem is not None:
                ver = service_elem.get("version", "")
                if ver:
                    port.version = f"{port.version} {ver}".strip()
            host.ports.append(port)

        # OS
        os_match_elem = host_elem.find(".//osmatch")
        if os_match_elem is not None:
            host.os_guess = os_match_elem.get("name", "")

        result.hosts.append(host)

    return result


def parse_nmap(content: str) -> NmapResult:
    """Auto-detect format and parse nmap output."""
    content = content.strip()
    if content.startswith("<?xml") or content.startswith("<nmaprun"):
        return parse_nmap_xml(content)
    return parse_nmap_normal(content)
