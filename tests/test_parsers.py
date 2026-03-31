"""Tests for PentBoard tool output parsers."""

import pytest
from pentboard.parsers.ffuf_parser import parse_ffuf
from pentboard.parsers.masscan_parser import parse_masscan
from pentboard.parsers.nmap_parser import parse_nmap, parse_nmap_normal, parse_nmap_xml
from pentboard.parsers.nuclei_parser import parse_nuclei
from pentboard.parsers.tool_parsers import (
    detect_tool,
    parse_gobuster,
    parse_nikto,
)


class TestNmapParser:
    def test_parse_basic_output(self, nmap_output):
        result = parse_nmap(nmap_output)
        assert len(result.hosts) == 4

    def test_parse_host_with_hostname(self, nmap_output):
        result = parse_nmap(nmap_output)
        host = next(h for h in result.hosts if h.ip == "10.0.0.5")
        assert host.hostname == "web01.acme.local"
        assert len(host.ports) == 7

    def test_parse_host_ip_only(self, nmap_output):
        result = parse_nmap(nmap_output)
        host = next(h for h in result.hosts if h.ip == "10.0.0.15")
        assert host.hostname == ""
        assert len(host.ports) == 3

    def test_parse_port_details(self, nmap_output):
        result = parse_nmap(nmap_output)
        host = next(h for h in result.hosts if h.ip == "10.0.0.1")
        ssh_port = next(p for p in host.ports if p.port == 22)
        assert ssh_port.protocol == "tcp"
        assert ssh_port.state == "open"
        assert ssh_port.service == "ssh"
        assert "OpenSSH" in ssh_port.version

    def test_parse_os_detection(self, nmap_output):
        result = parse_nmap(nmap_output)
        host = next(h for h in result.hosts if h.ip == "10.0.0.10")
        assert "Linux" in host.os_guess

    def test_parse_empty_input(self):
        result = parse_nmap("")
        assert len(result.hosts) == 0

    def test_parse_garbage_input(self):
        result = parse_nmap("this is not nmap output\nrandom garbage\n123")
        assert len(result.hosts) == 0

    def test_parse_single_host(self):
        output = """Nmap scan report for 192.168.1.1
Host is up (0.001s latency).
PORT   STATE SERVICE
80/tcp open  http
"""
        result = parse_nmap(output)
        assert len(result.hosts) == 1
        assert result.hosts[0].ip == "192.168.1.1"
        assert len(result.hosts[0].ports) == 1

    def test_auto_detect_xml(self):
        xml = '<?xml version="1.0"?><nmaprun></nmaprun>'
        result = parse_nmap(xml)
        assert len(result.hosts) == 0
        assert len(result.errors) == 0


class TestGobusterParser:
    def test_parse_dir_mode(self, gobuster_output):
        result = parse_gobuster(gobuster_output)
        assert len(result.results) > 0
        assert result.target == "http://10.0.0.5"

    def test_parse_specific_paths(self, gobuster_output):
        result = parse_gobuster(gobuster_output)
        admin = next((r for r in result.results if r.url == "/admin"), None)
        assert admin is not None
        assert admin.status == 200

    def test_parse_redirect(self, gobuster_output):
        result = parse_gobuster(gobuster_output)
        api = next((r for r in result.results if r.url == "/api"), None)
        assert api is not None
        assert api.status == 301
        assert "api" in api.redirect

    def test_parse_empty_input(self):
        result = parse_gobuster("")
        assert len(result.results) == 0

    def test_parse_garbage_input(self):
        result = parse_gobuster("not gobuster output")
        assert len(result.results) == 0


class TestNiktoParser:
    def test_parse_basic_output(self, nikto_output):
        result = parse_nikto(nikto_output)
        assert result.target == "web01.acme.local"
        assert result.ip == "10.0.0.5"
        assert result.port == 80

    def test_parse_findings(self, nikto_output):
        result = parse_nikto(nikto_output)
        assert len(result.findings) > 0

    def test_parse_osvdb(self, nikto_output):
        result = parse_nikto(nikto_output)
        osvdb_findings = [f for f in result.findings if f.osvdb]
        assert len(osvdb_findings) > 0

    def test_parse_empty_input(self):
        result = parse_nikto("")
        assert len(result.findings) == 0


class TestMasscanParser:
    """Tests for masscan text and JSON parsing."""

    def test_parse_text_output(self, masscan_output):
        """Parse standard masscan text output with 4 hosts."""
        result = parse_masscan(masscan_output)
        assert len(result.hosts) == 4

    def test_parse_text_host_ports(self, masscan_output):
        """Port counts match the example file per host."""
        result = parse_masscan(masscan_output)
        host_map = {h.ip: h for h in result.hosts}
        assert len(host_map["10.0.0.1"].ports) == 4
        assert len(host_map["10.0.0.5"].ports) == 7
        assert len(host_map["10.0.0.10"].ports) == 2
        assert len(host_map["10.0.0.15"].ports) == 3

    def test_parse_text_port_details(self, masscan_output):
        """Individual port fields are parsed correctly."""
        result = parse_masscan(masscan_output)
        host = next(h for h in result.hosts if h.ip == "10.0.0.1")
        port22 = next(p for p in host.ports if p.port == 22)
        assert port22.protocol == "tcp"
        assert port22.status == "open"

    def test_parse_json_output(self, masscan_json):
        """Parse masscan JSON output and merge per-IP entries."""
        result = parse_masscan(masscan_json)
        assert len(result.hosts) == 3
        host_map = {h.ip: h for h in result.hosts}
        assert len(host_map["10.0.0.1"].ports) == 4
        assert len(host_map["10.0.0.5"].ports) == 5
        assert len(host_map["10.0.0.10"].ports) == 2

    def test_parse_empty_input(self):
        """Empty string returns empty result."""
        result = parse_masscan("")
        assert len(result.hosts) == 0

    def test_parse_garbage_input(self):
        """Non-masscan text returns empty result gracefully."""
        result = parse_masscan("this is not masscan output\nrandom stuff")
        assert len(result.hosts) == 0

    def test_parse_bad_json(self):
        """Malformed JSON returns errors list, no crash."""
        result = parse_masscan("[{invalid json")
        assert len(result.errors) > 0
        assert len(result.hosts) == 0

    def test_scan_info_extracted(self, masscan_output):
        """The scan header line is captured as scan_info."""
        result = parse_masscan(masscan_output)
        assert "masscan" in result.scan_info.lower()

    def test_list_format(self):
        """Parse masscan list (-oL) format."""
        output = "Host: 10.0.0.1 ()   Ports: 22/open/tcp//ssh//, 80/open/tcp//http//"
        result = parse_masscan(output)
        assert len(result.hosts) == 1
        assert len(result.hosts[0].ports) == 2


class TestFfufParser:
    """Tests for ffuf JSON and text parsing."""

    def test_parse_json_output(self, ffuf_json):
        """Parse ffuf JSON output with all results."""
        result = parse_ffuf(ffuf_json)
        assert len(result.results) == 14
        assert result.target_url == "http://10.0.0.5/FUZZ"
        assert result.method == "GET"

    def test_parse_json_entry_details(self, ffuf_json):
        """Individual entry fields are parsed correctly from JSON."""
        result = parse_ffuf(ffuf_json)
        admin = next(e for e in result.results if e.input_word == "admin")
        assert admin.status == 200
        assert admin.length == 4521
        assert admin.url == "http://10.0.0.5/admin"
        assert admin.host == "10.0.0.5"

    def test_parse_json_redirect(self, ffuf_json):
        """Redirect location is captured."""
        result = parse_ffuf(ffuf_json)
        api = next(e for e in result.results if e.input_word == "api")
        assert api.status == 301
        assert "api" in api.redirect_location

    def test_parse_text_output(self, ffuf_text):
        """Parse ffuf plain text output."""
        result = parse_ffuf(ffuf_text)
        assert len(result.results) == 14
        assert "FUZZ" in result.target_url

    def test_parse_text_entry_details(self, ffuf_text):
        """Individual entry fields are parsed correctly from text."""
        result = parse_ffuf(ffuf_text)
        admin = next(e for e in result.results if e.input_word == "admin")
        assert admin.status == 200
        assert admin.length == 4521

    def test_parse_text_url_construction(self, ffuf_text):
        """URL is reconstructed from target template and fuzz word."""
        result = parse_ffuf(ffuf_text)
        admin = next(e for e in result.results if e.input_word == "admin")
        assert admin.url == "http://10.0.0.5/admin"

    def test_parse_empty_input(self):
        """Empty string returns empty result."""
        result = parse_ffuf("")
        assert len(result.results) == 0

    def test_parse_bad_json(self):
        """Malformed JSON returns errors list, no crash."""
        result = parse_ffuf("{invalid json")
        assert len(result.errors) > 0
        assert len(result.results) == 0

    def test_parse_garbage_text(self):
        """Non-ffuf text returns empty result."""
        result = parse_ffuf("not ffuf output\nrandom lines")
        assert len(result.results) == 0


class TestNucleiParser:
    """Tests for nuclei JSONL and text parsing."""

    def test_parse_jsonl_output(self, nuclei_jsonl):
        """Parse nuclei JSONL output with all findings."""
        result = parse_nuclei(nuclei_jsonl)
        assert len(result.findings) == 8

    def test_parse_jsonl_severity_levels(self, nuclei_jsonl):
        """All severity levels are captured from JSONL."""
        result = parse_nuclei(nuclei_jsonl)
        severities = {f.info.severity for f in result.findings}
        assert severities == {"critical", "high", "medium", "low", "info"}

    def test_parse_jsonl_critical_finding(self, nuclei_jsonl):
        """Critical finding details are fully parsed."""
        result = parse_nuclei(nuclei_jsonl)
        log4j = next(f for f in result.findings if f.template_id == "cve-2021-44228")
        assert log4j.info.severity == "critical"
        assert log4j.info.name == "Apache Log4j RCE"
        assert "CVE-2021-44228" in log4j.info.classification.cve_ids
        assert "CWE-502" in log4j.info.classification.cwe_ids
        assert log4j.info.classification.cvss_score == 10.0
        assert log4j.ip == "10.0.0.5"
        assert "8443" in log4j.matched_at

    def test_parse_jsonl_tags(self, nuclei_jsonl):
        """Tags list is parsed correctly."""
        result = parse_nuclei(nuclei_jsonl)
        log4j = next(f for f in result.findings if f.template_id == "cve-2021-44228")
        assert "cve" in log4j.info.tags
        assert "rce" in log4j.info.tags

    def test_parse_text_output(self, nuclei_text):
        """Parse nuclei terminal text output."""
        result = parse_nuclei(nuclei_text)
        assert len(result.findings) == 8

    def test_parse_text_severity(self, nuclei_text):
        """Severity is extracted from text format."""
        result = parse_nuclei(nuclei_text)
        crits = [f for f in result.findings if f.info.severity == "critical"]
        assert len(crits) == 2

    def test_parse_text_template_id(self, nuclei_text):
        """Template ID is extracted from text format."""
        result = parse_nuclei(nuclei_text)
        ids = {f.template_id for f in result.findings}
        assert "cve-2021-44228" in ids
        assert "directory-listing" in ids

    def test_parse_text_ip_extraction(self, nuclei_text):
        """IP address is extracted from the matched URL."""
        result = parse_nuclei(nuclei_text)
        for f in result.findings:
            assert f.ip in ("10.0.0.1", "10.0.0.5")

    def test_parse_empty_input(self):
        """Empty string returns empty result."""
        result = parse_nuclei("")
        assert len(result.findings) == 0

    def test_parse_garbage_input(self):
        """Non-nuclei text returns empty result."""
        result = parse_nuclei("this is not nuclei output")
        assert len(result.findings) == 0

    def test_parse_bad_jsonl_line(self):
        """Bad JSONL lines are skipped, valid ones still parsed."""
        content = '{"template-id":"test","info":{"name":"Test","severity":"info"},"host":"x","matched-at":"x","ip":"1.2.3.4"}\n{broken json\n'
        result = parse_nuclei(content)
        assert len(result.findings) == 1
        assert len(result.errors) == 1


class TestToolDetection:
    def test_detect_nmap(self):
        assert detect_tool("Nmap scan report for 10.0.0.1") == "nmap"

    def test_detect_nmap_xml(self):
        assert detect_tool("<nmaprun scanner='nmap'>") == "nmap"

    def test_detect_masscan_text(self):
        assert detect_tool("Starting masscan 1.3.2\nDiscovered open port 80/tcp on 10.0.0.1") == "masscan"

    def test_detect_masscan_discovered(self):
        assert detect_tool("Discovered open port 22/tcp on 10.0.0.5") == "masscan"

    def test_detect_nuclei_text(self):
        assert detect_tool("[2026-03-30] [cve-2021-44228] [http] [critical] http://10.0.0.5/") == "nuclei"

    def test_detect_nuclei_jsonl(self):
        assert detect_tool('{"template-id":"cve-2021-44228","info":{"severity":"critical"}}') == "nuclei"

    def test_detect_ffuf_text(self):
        assert detect_tool("ffuf v2.1.0\nadmin [Status: 200, Size: 4521]") == "ffuf"

    def test_detect_ffuf_json(self):
        assert detect_tool('{"results": [{"status": 200, "length": 100}]}') == "ffuf"

    def test_detect_gobuster(self):
        assert detect_tool("Gobuster v3.6\n/admin (Status: 200)") == "gobuster"

    def test_detect_nikto(self):
        assert detect_tool("- Nikto v2.5.0\n+ Target IP: 10.0.0.1") == "nikto"

    def test_detect_unknown(self):
        assert detect_tool("random text") == "unknown"

    def test_detect_empty(self):
        assert detect_tool("") == "unknown"
