<p align="center">
  <h1 align="center">PentBoard</h1>
  <p align="center">
    <strong>Terminal Pentest Mission Control</strong>
  </p>
  <p align="center">
    A TUI dashboard for managing penetration testing engagements, tracking targets, importing tool output, correlating findings, and generating reports. All from your terminal.
  </p>
  <p align="center">
    <a href="https://github.com/AliRai7/pentboard/stargazers"><img src="https://img.shields.io/github/stars/AliRai7/pentboard?style=flat-square&color=yellow" alt="Stars"></a>
    <a href="https://pypi.org/project/pentboard/"><img src="https://img.shields.io/pypi/v/pentboard?style=flat-square&color=blue" alt="PyPI"></a>
    <a href="https://github.com/AliRai7/pentboard/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
    <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.10+-blue?style=flat-square" alt="Python"></a>
  </p>
</p>

---

## The Problem

Every pentester knows this workflow:

1. Open 15 terminal tabs
2. Run nmap in one, gobuster in another, nikto in a third
3. Copy-paste output into random text files
4. Lose track of which hosts you've tested
5. Spend 3 hours writing the report at 2am
6. Hate your life

**PentBoard fixes this.**

## What It Does

PentBoard is a terminal-native mission control for penetration testing engagements. Think of it as your pentest cockpit.

- **Engagement Management** -- Create and switch between pentest jobs with scope, dates, and client info
- **Target Tracking** -- Track every host with status (recon, scanning, exploiting, compromised)
- **Tool Output Import** -- Paste or pipe nmap, gobuster, or nikto output and PentBoard auto-parses it into structured findings
- **Findings Dashboard** -- All findings sorted by severity (Critical/High/Medium/Low/Info) with CWE, CVSS, and evidence
- **Report Generation** -- One-click Markdown pentest report with executive summary, severity breakdown, and detailed findings
- **100% Offline** -- SQLite database, no cloud, no telemetry, your data stays yours

## Quick Start

```bash
# Install
pip install pentboard

# Or install from source
git clone https://github.com/AliRai7/pentboard.git
cd pentboard
pip install -e .

# Run
pentboard
```

## Usage

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `n` | New engagement |
| `t` | Add target |
| `i` | Import tool output |
| `r` | Generate report |
| `q` | Quit |

### Import Tool Output

PentBoard auto-detects and parses output from:

| Tool | Format | What Gets Imported |
|------|--------|--------------------|
| **nmap** | Normal (-oN) and XML (-oX) | Hosts, ports, services, OS detection |
| **gobuster** | Dir mode output | Discovered paths with status codes |
| **nikto** | Standard output | Web vulnerabilities and misconfigurations |

**More parsers coming soon:** masscan, ffuf, feroxbuster, sqlmap, nuclei

### Example Workflow

```bash
# 1. Launch PentBoard
pentboard

# 2. Create engagement (press 'n')
#    Name: "Acme Corp External"
#    Scope: "10.0.0.0/24, acme.com"

# 3. Run your scans in another terminal
nmap -sV -oN scan.txt 10.0.0.0/24

# 4. Import results (press 'i')
#    Paste the nmap output

# 5. PentBoard auto-creates targets and findings

# 6. Generate report (press 'r')
#    One-click Markdown report ready to go
```

### Report Generation

PentBoard generates professional Markdown reports including:

- Executive summary with finding counts
- Severity breakdown table
- Full target inventory with open ports
- Detailed findings with evidence and remediation
- Auto-formatted for client delivery

Export to file with one click, or pipe to pandoc for PDF/DOCX.

## Architecture

```
pentboard/
  pentboard/
    app.py              # Main TUI application (Textual)
    models/
      database.py       # SQLite database models & CRUD
    parsers/
      nmap_parser.py    # Nmap normal + XML parser
      tool_parsers.py   # Gobuster, Nikto, auto-detection
    widgets/            # Custom TUI widgets (coming soon)
    utils/
      report.py         # Markdown report generator
  tests/
  pyproject.toml
```

## Roadmap

### v0.2 -- More Parsers & Evidence
- [ ] masscan, ffuf, feroxbuster parsers
- [ ] nuclei output parser
- [ ] Screenshot attachment support
- [ ] Finding templates (OWASP Top 10)

### v0.3 -- ReconFlow (Interactive Graph)
- [ ] Terminal-based network graph visualization
- [ ] Interactive host/service/vuln exploration
- [ ] Attack path mapping

### v0.4 -- LootBox (Evidence Manager)
- [ ] Auto-capture tool output as evidence
- [ ] Evidence chain builder
- [ ] Export to PDF via pandoc

### v0.5 -- Integrations
- [ ] Pipe mode: `nmap -sV 10.0.0.1 | pentboard import`
- [ ] Metasploit database import
- [ ] Burp Suite XML import
- [ ] Custom parser plugin system

## Contributing

Contributions are welcome! Whether it's new tool parsers, TUI improvements, or bug fixes.

```bash
# Clone and install dev dependencies
git clone https://github.com/AliRai7/pentboard.git
cd pentboard
pip install -e ".[dev]"

# Run in dev mode
textual run --dev pentboard/app.py
```

### Adding a New Parser

1. Create a parser in `pentboard/parsers/`
2. Add detection logic to `detect_tool()` in `tool_parsers.py`
3. Add import handling in `app.py` `_process_import()`
4. Submit a PR!

## Disclaimer

PentBoard is designed for authorized penetration testing and security assessments only. Only use this tool on systems you have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool.

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  Built by <a href="https://github.com/AliRai7">Ali Rai</a> with Textual
</p>
