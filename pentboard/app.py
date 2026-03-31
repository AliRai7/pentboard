"""PentBoard - Terminal Pentest Mission Control TUI Application."""

import json
import os
import re
import sys
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    ListItem,
    ListView,
    Markdown,
    OptionList,
    Placeholder,
    Rule,
    Select,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
)

from pentboard.models.database import (
    Database,
    Engagement,
    Finding,
    Severity,
    Target,
    TargetStatus,
)
from pentboard.parsers.ffuf_parser import parse_ffuf
from pentboard.parsers.masscan_parser import parse_masscan
from pentboard.parsers.nmap_parser import parse_nmap
from pentboard.parsers.nuclei_parser import parse_nuclei
from pentboard.parsers.tool_parsers import detect_tool, parse_gobuster, parse_nikto
from pentboard.utils.report import generate_report
from pentboard.widgets.recon_graph import ReconGraph


# ─── Severity Colors ─────────────────────────────────────────────────────────

SEVERITY_COLORS = {
    "critical": "bold white on dark_red",
    "high": "bold white on red",
    "medium": "bold black on yellow",
    "low": "bold white on dodger_blue2",
    "info": "dim white on grey37",
}

SEVERITY_LABELS = {
    "critical": " CRIT ",
    "high": " HIGH ",
    "medium": " MED  ",
    "low": " LOW  ",
    "info": " INFO ",
}

STATUS_STYLES = {
    "not_started": ("dim", "[ ]"),
    "recon": ("bright_cyan", "[~]"),
    "scanning": ("bright_yellow", "[S]"),
    "exploiting": ("bold bright_red", "[!]"),
    "compromised": ("bold red", "[X]"),
    "completed": ("bold bright_green", "[+]"),
}

# ─── ASCII Art Banner ────────────────────────────────────────────────────────

SPLASH_BANNER = """\
[bold bright_green]
  ____            _   ____                      _
 |  _ \\ ___  _ __ | |_| __ )  ___   __ _ _ __ __| |
 | |_) / _ \\| '_ \\| __|  _ \\ / _ \\ / _` | '__/ _` |
 |  __/  __/| | | | |_| |_) | (_) | (_| | | | (_| |
 |_|   \\___||_| |_|\\__|____/ \\___/ \\__,_|_|  \\__,_|
[/bold bright_green]
[dim bright_green]Terminal Pentest Mission Control[/dim bright_green]                     [dim]v0.1.0[/dim]

[bright_green]n[/bright_green] New Engagement    [bright_green]i[/bright_green] Import Output    [bright_green]g[/bright_green] Graph View
[bright_green]t[/bright_green] Add Target        [bright_green]r[/bright_green] Generate Report  [bright_green]?[/bright_green] Help
[bright_green]q[/bright_green] Quit

[dim]Select an engagement below or press [bold bright_green]n[/bold bright_green] to begin.[/dim]"""


# ─── Rich Text helpers ───────────────────────────────────────────────────────

def _severity_cell(severity: str) -> Text:
    """Build a color-coded Rich Text badge for a severity value."""
    label = SEVERITY_LABELS.get(severity, f" {severity.upper()} ")
    style = SEVERITY_COLORS.get(severity, "")
    return Text(label, style=style)


def _status_cell(status: str) -> Text:
    """Build a color-coded Rich Text cell for a target status."""
    style, icon = STATUS_STYLES.get(status, ("dim", "[ ]"))
    return Text(f"{icon} {status.replace('_', ' ')}", style=style)


# ─── Modal: New Engagement ────────────────────────────────────────────────────

class NewEngagementScreen(ModalScreen[dict]):
    """Modal for creating a new engagement."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    NewEngagementScreen {
        align: center middle;
    }
    #new-engagement-container {
        width: 70;
        height: auto;
        max-height: 22;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #new-engagement-container Input {
        margin-bottom: 1;
    }
    #new-engagement-container .field-label {
        margin-bottom: 0;
        color: $text;
    }
    #new-engagement-container .modal-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 0;
    }
    #eng-btn-row {
        height: 3;
        align: center middle;
        margin-top: 1;
    }
    #eng-btn-row Button {
        margin: 0 2;
        min-width: 16;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="new-engagement-container"):
            yield Label("NEW ENGAGEMENT", classes="modal-title")
            yield Rule()
            yield Label("Name *", classes="field-label")
            yield Input(placeholder="e.g. Acme Corp External Pentest", id="eng-name")
            yield Label("Client", classes="field-label")
            yield Input(placeholder="e.g. Acme Corporation", id="eng-client")
            yield Label("Scope", classes="field-label")
            yield Input(placeholder="e.g. 10.0.0.0/24, acme.com", id="eng-scope")
            with Horizontal(id="eng-btn-row"):
                yield Button("Create", variant="success", id="btn-create")
                yield Button("Cancel", variant="error", id="btn-cancel")

    def _submit_form(self) -> None:
        """Validate and submit the form."""
        name = self.query_one("#eng-name", Input).value.strip()
        if not name:
            self.notify("Name is required!", severity="error")
            self.query_one("#eng-name", Input).focus()
            return
        self.dismiss({
            "name": name,
            "client": self.query_one("#eng-client", Input).value.strip(),
            "scope": self.query_one("#eng-scope", Input).value.strip(),
        })

    @on(Button.Pressed, "#btn-create")
    def on_create(self) -> None:
        """Handle Create button press."""
        self._submit_form()

    @on(Button.Pressed, "#btn-cancel")
    def on_cancel_btn(self) -> None:
        """Handle Cancel button press."""
        self.dismiss(None)

    @on(Input.Submitted)
    def on_input_submitted(self) -> None:
        """Handle Enter key in any input field."""
        self._submit_form()

    def action_cancel(self) -> None:
        self.dismiss(None)


# ─── Modal: Add Target ────────────────────────────────────────────────────────

class AddTargetScreen(ModalScreen[dict]):
    """Modal for adding a target."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    AddTargetScreen {
        align: center middle;
    }
    #add-target-container {
        width: 60;
        height: auto;
        max-height: 22;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #add-target-container Input {
        margin-bottom: 1;
    }
    #add-target-container .field-label {
        margin-bottom: 0;
        color: $text;
    }
    #add-target-container .modal-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 0;
    }
    .target-btn-row {
        height: 3;
        align: center middle;
        margin-top: 1;
    }
    .target-btn-row Button {
        margin: 0 2;
        min-width: 16;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="add-target-container"):
            yield Label("ADD TARGET", classes="modal-title")
            yield Rule()
            yield Label("IP Address *", classes="field-label")
            yield Input(placeholder="e.g. 192.168.1.100", id="target-ip")
            yield Label("Hostname", classes="field-label")
            yield Input(placeholder="e.g. web01.acme.com", id="target-hostname")
            yield Label("Notes", classes="field-label")
            yield Input(placeholder="DMZ web server, etc.", id="target-notes")
            with Horizontal(classes="target-btn-row"):
                yield Button("Add", variant="success", id="btn-add-target")
                yield Button("Cancel", variant="error", id="btn-cancel-target")

    def _submit_form(self) -> None:
        """Validate and submit the form."""
        ip = self.query_one("#target-ip", Input).value.strip()
        if not ip:
            self.notify("IP address is required!", severity="error")
            self.query_one("#target-ip", Input).focus()
            return
        self.dismiss({
            "ip": ip,
            "hostname": self.query_one("#target-hostname", Input).value.strip(),
            "notes": self.query_one("#target-notes", Input).value.strip(),
        })

    @on(Button.Pressed, "#btn-add-target")
    def on_add(self) -> None:
        self._submit_form()

    @on(Button.Pressed, "#btn-cancel-target")
    def on_cancel_btn(self) -> None:
        self.dismiss(None)

    @on(Input.Submitted)
    def on_input_submitted(self) -> None:
        """Handle Enter key in any input field."""
        self._submit_form()

    def action_cancel(self) -> None:
        self.dismiss(None)


# ─── Modal: Import Tool Output ────────────────────────────────────────────────

class ImportScreen(ModalScreen[str]):
    """Modal for importing tool output."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]
    DEFAULT_CSS = """
    ImportScreen {
        align: center middle;
    }
    #import-container {
        width: 90;
        height: 35;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #import-container TextArea {
        height: 20;
    }
    #import-container .field-label {
        margin-bottom: 0;
        color: $text;
    }
    #import-container .modal-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        margin-bottom: 0;
    }
    .import-btn-row {
        height: 3;
        align: center middle;
        margin-top: 1;
    }
    .import-btn-row Button {
        margin: 0 2;
        min-width: 16;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="import-container"):
            yield Label("IMPORT TOOL OUTPUT", classes="modal-title")
            yield Rule()
            yield Label(
                "Paste nmap, masscan, ffuf, nuclei, gobuster, or nikto output:",
                classes="field-label",
            )
            yield TextArea(id="import-text", language=None)
            with Horizontal(classes="import-btn-row"):
                yield Button("Import", variant="success", id="btn-import")
                yield Button("Cancel", variant="error", id="btn-cancel-import")

    @on(Button.Pressed, "#btn-import")
    def on_import(self) -> None:
        text = self.query_one("#import-text", TextArea).text.strip()
        if not text:
            self.notify("Paste some output first!", severity="error")
            return
        self.dismiss(text)

    @on(Button.Pressed, "#btn-cancel-import")
    def on_cancel_btn(self) -> None:
        self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)


# ─── Modal: Finding Detail (from Graph) ──────────────────────────────────────

class FindingDetailScreen(ModalScreen[None]):
    """Modal showing full details of a finding selected from the graph."""

    BINDINGS = [Binding("escape", "dismiss_modal", "Close")]
    DEFAULT_CSS = """
    FindingDetailScreen {
        align: center middle;
    }
    #finding-detail-container {
        width: 80;
        height: auto;
        max-height: 32;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #finding-detail-container Static {
        margin-bottom: 0;
    }
    .detail-btn-row {
        height: 3;
        align: center middle;
        margin-top: 1;
    }
    """

    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        f = self.finding
        sev_color = SEVERITY_COLORS.get(f.severity, "")
        with Vertical(id="finding-detail-container"):
            yield Static(f"[bold]{f.title}[/bold]")
            yield Rule()
            yield Static(
                f"[{sev_color}] {f.severity.upper()} [/{sev_color}]"
                f"  Status: {f.status.replace('_', ' ')}"
            )
            if f.port:
                yield Static(f"Port: [bold]{f.port}[/bold]  Service: {f.service or 'N/A'}")
            if f.tool_source:
                yield Static(f"Tool: {f.tool_source}")
            if f.cwe:
                yield Static(f"CWE: {f.cwe}")
            yield Rule()
            if f.description:
                yield Static(f"[bold]Description[/bold]\n{f.description}")
            if f.evidence:
                yield Static(f"[bold]Evidence[/bold]\n{f.evidence}")
            if f.remediation:
                yield Static(f"[bold]Remediation[/bold]\n{f.remediation}")
            with Horizontal(classes="detail-btn-row"):
                yield Button("Close", variant="primary", id="btn-close-detail")

    @on(Button.Pressed, "#btn-close-detail")
    def on_close(self) -> None:
        self.dismiss(None)

    def action_dismiss_modal(self) -> None:
        self.dismiss(None)


# ─── Modal: Help Screen ─────────────────────────────────────────────────────

class HelpScreen(ModalScreen[None]):
    """Modal showing keybindings and feature reference."""

    BINDINGS = [
        Binding("escape", "dismiss_help", "Close"),
        Binding("question_mark", "dismiss_help", "Close", show=False),
    ]
    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    #help-container {
        width: 72;
        height: auto;
        max-height: 36;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #help-container Static {
        margin-bottom: 0;
    }
    .help-btn-row {
        height: 3;
        align: center middle;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="help-container"):
            yield Static(
                "[bold bright_green]PentBoard[/bold bright_green]"
                " [dim]-- Keyboard Reference[/dim]"
            )
            yield Rule()
            yield Static(
                "[bold]Navigation[/bold]\n"
                "  [bright_green]Tab[/bright_green] / [bright_green]Shift+Tab[/bright_green]"
                "      Switch between tabs\n"
                "  [bright_green]Up[/bright_green] / [bright_green]Down[/bright_green]"
                "            Navigate table rows\n"
                "  [bright_green]Enter[/bright_green]"
                "                   Select / activate item\n"
            )
            yield Static(
                "[bold]Actions[/bold]\n"
                "  [bright_green]n[/bright_green]"
                "                       New engagement\n"
                "  [bright_green]t[/bright_green]"
                "                       Add target\n"
                "  [bright_green]i[/bright_green]"
                "                       Import tool output\n"
                "  [bright_green]g[/bright_green]"
                "                       Jump to ReconFlow graph\n"
                "  [bright_green]r[/bright_green]"
                "                       Generate report\n"
                "  [bright_green]?[/bright_green]"
                "                       This help screen\n"
                "  [bright_green]q[/bright_green]"
                "                       Quit\n"
            )
            yield Static(
                "[bold]Supported Tools[/bold]\n"
                "  [bright_green]nmap[/bright_green]      Scan import (normal + XML)\n"
                "  [bright_green]masscan[/bright_green]   Fast port scan (text + JSON + list)\n"
                "  [bright_green]ffuf[/bright_green]      Web fuzzer (JSON + text)\n"
                "  [bright_green]nuclei[/bright_green]    Vuln scanner (JSONL + text)\n"
                "  [bright_green]gobuster[/bright_green]  Dir/vhost brute (text)\n"
                "  [bright_green]nikto[/bright_green]     Web scanner (text)\n"
            )
            yield Static(
                "[bold]Tabs[/bold]\n"
                "  [dim]Dashboard[/dim]   Engagement overview + stats\n"
                "  [dim]Targets[/dim]     Host/IP management\n"
                "  [dim]Findings[/dim]    Vulnerability tracker\n"
                "  [dim]Graph[/dim]       ReconFlow network visualization\n"
                "  [dim]Report[/dim]      Markdown report export\n"
            )
            with Horizontal(classes="help-btn-row"):
                yield Button("Close", variant="primary", id="btn-close-help")

    @on(Button.Pressed, "#btn-close-help")
    def on_close(self) -> None:
        self.dismiss(None)

    def action_dismiss_help(self) -> None:
        self.dismiss(None)


# ─── Main App ─────────────────────────────────────────────────────────────────

class PentBoardApp(App):
    """PentBoard - Terminal Pentest Mission Control."""

    TITLE = "PentBoard v0.1.0"
    SUB_TITLE = "Terminal Pentest Mission Control"

    CSS = """
    Screen {
        background: $surface;
    }

    /* Status bar */
    #status-bar {
        dock: bottom;
        height: 1;
        background: $primary-background;
        color: $text;
        padding: 0 2;
    }

    /* ── Dashboard ── */
    #dashboard {
        height: 100%;
        padding: 1 2;
    }
    #no-engagement {
        height: auto;
        content-align: center middle;
        text-align: center;
        margin-bottom: 1;
    }
    #action-bar {
        height: 3;
        align: center middle;
        margin-bottom: 1;
    }
    #action-bar Button {
        margin: 0 1;
        min-width: 20;
    }
    #stats-row {
        height: 5;
        margin-bottom: 1;
    }
    .stat-box {
        width: 1fr;
        height: 100%;
        content-align: center middle;
        text-align: center;
        margin: 0 1;
        padding: 0 2;
    }
    .stat-box.stat-targets {
        border: solid #00ff00;
    }
    .stat-box.stat-compromised {
        border: solid #ffff00;
    }
    .stat-box.stat-critical {
        border: solid red;
    }
    .stat-box.stat-high {
        border: solid #ff8c00;
    }
    #engagement-info {
        height: 3;
        padding: 0 2;
        margin-bottom: 1;
        border: solid $primary;
    }
    #engagement-list-container {
        height: 1fr;
    }

    /* ── Targets tab ── */
    #targets-table {
        height: 1fr;
    }
    #target-actions {
        height: 3;
        align: left middle;
        margin: 1 0;
        padding: 0 1;
    }
    #target-actions Button {
        margin: 0 1;
        min-width: 16;
    }

    /* ── Findings tab ── */
    #findings-table {
        height: 1fr;
    }
    #finding-actions {
        height: 3;
        align: left middle;
        margin: 1 0;
        padding: 0 1;
    }
    #finding-actions Button {
        margin: 0 1;
        min-width: 16;
    }

    /* ── Report tab ── */
    #report-view {
        height: 1fr;
        padding: 1;
    }
    #report-actions {
        height: 3;
        align: left middle;
        margin: 1 0;
        padding: 0 1;
    }
    #report-actions Button {
        margin: 0 1;
        min-width: 16;
    }

    /* ── Graph tab ── */
    #tab-graph {
        height: 100%;
    }
    """

    BINDINGS = [
        Binding("n", "new_engagement", "New Engagement"),
        Binding("t", "add_target", "Add Target"),
        Binding("i", "import_output", "Import"),
        Binding("g", "show_graph", "Graph"),
        Binding("r", "gen_report", "Report"),
        Binding("question_mark", "show_help", "Help", key_display="?"),
        Binding("q", "quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self.db = Database()
        self.current_engagement_id: int | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent("Dashboard", "Targets", "Findings", "Graph", "Report"):
            # Dashboard
            with TabPane("Dashboard", id="tab-dashboard"):
                with Vertical(id="dashboard"):
                    yield Static(SPLASH_BANNER, id="no-engagement")
                    with Horizontal(id="action-bar"):
                        yield Button("New Engagement", variant="success", id="btn-new-eng")
                        yield Button("Import Output", variant="primary", id="btn-import-output")
                    with Horizontal(id="stats-row"):
                        yield Static(
                            "[bold bright_green]TARGETS[/bold bright_green]\n"
                            "[bold bright_green]--[/bold bright_green]",
                            classes="stat-box stat-targets",
                        )
                        yield Static(
                            "[bold bright_yellow]COMPROMISED[/bold bright_yellow]\n"
                            "[bold bright_yellow]--[/bold bright_yellow]",
                            classes="stat-box stat-compromised",
                        )
                        yield Static(
                            "[bold red]CRITICAL[/bold red]\n"
                            "[bold red]--[/bold red]",
                            classes="stat-box stat-critical",
                        )
                        yield Static(
                            "[bold dark_orange]HIGH[/bold dark_orange]\n"
                            "[bold dark_orange]--[/bold dark_orange]",
                            classes="stat-box stat-high",
                        )
                    yield Static("", id="engagement-info")
                    yield DataTable(id="engagement-list")

            # Targets
            with TabPane("Targets", id="tab-targets"):
                with Vertical():
                    with Horizontal(id="target-actions"):
                        yield Button("Add Target", variant="success", id="btn-add-target-tab")
                        yield Button("Import Scan", variant="primary", id="btn-import-scan")
                    yield DataTable(id="targets-table")

            # Findings
            with TabPane("Findings", id="tab-findings"):
                with Vertical():
                    with Horizontal(id="finding-actions"):
                        yield Button("Import Output", variant="primary", id="btn-import-findings")
                    yield DataTable(id="findings-table")

            # Graph (ReconFlow)
            with TabPane("Graph", id="tab-graph"):
                yield ReconGraph(self.db, id="recon-graph")

            # Report
            with TabPane("Report", id="tab-report"):
                with Vertical():
                    with Horizontal(id="report-actions"):
                        yield Button("Generate Report", variant="success", id="btn-gen-report")
                        yield Button("Export to File", variant="primary", id="btn-export-report")
                    yield VerticalScroll(
                        Markdown("*Select an engagement and click Generate Report*", id="report-md"),
                        id="report-view",
                    )

        yield Static("", id="status-bar")
        yield Footer()

    def on_mount(self) -> None:
        """Initialize tables and load engagements."""
        # Engagement list table
        eng_table = self.query_one("#engagement-list", DataTable)
        eng_table.add_columns("ID", "Name", "Client", "Status", "Targets", "Findings", "Created")
        eng_table.cursor_type = "row"
        eng_table.zebra_stripes = True

        # Targets table
        tgt_table = self.query_one("#targets-table", DataTable)
        tgt_table.add_columns("ID", "IP", "Hostname", "OS", "Status", "Open Ports", "Notes")
        tgt_table.cursor_type = "row"
        tgt_table.zebra_stripes = True

        # Findings table
        fnd_table = self.query_one("#findings-table", DataTable)
        fnd_table.add_columns("ID", "Severity", "Title", "Target", "Port", "Service", "Tool", "Status")
        fnd_table.cursor_type = "row"
        fnd_table.zebra_stripes = True

        self._refresh_engagement_list()
        self._update_status_bar()

    def _update_status_bar(self) -> None:
        """Update the bottom status bar with current engagement info."""
        bar = self.query_one("#status-bar", Static)
        if not self.current_engagement_id:
            bar.update(
                "[dim]No engagement loaded[/dim]"
                "  [bright_green]|[/bright_green]  "
                "[dim]Press [bold]n[/bold] to create one[/dim]"
            )
            return

        eng = self.db.get_engagement(self.current_engagement_id)
        if not eng:
            return

        stats = self.db.get_engagement_stats(self.current_engagement_id)
        sev = stats["findings_by_severity"]

        bar.update(
            f"[bold bright_green]{eng.name}[/bold bright_green]"
            f"  [bright_green]|[/bright_green]  "
            f"[bold]{stats['targets']}[/bold] targets  "
            f"[bright_green]|[/bright_green]  "
            f"[bold red]{sev.get('critical', 0)}[/bold red]C "
            f"[bold dark_orange]{sev.get('high', 0)}[/bold dark_orange]H "
            f"[bold yellow]{sev.get('medium', 0)}[/bold yellow]M "
            f"[bold dodger_blue2]{sev.get('low', 0)}[/bold dodger_blue2]L "
            f"[dim]{sev.get('info', 0)}I[/dim]"
            f"  [bright_green]|[/bright_green]  "
            f"[bold]{stats['total_findings']}[/bold] findings"
        )

    def _refresh_engagement_list(self) -> None:
        """Reload the engagement list table."""
        table = self.query_one("#engagement-list", DataTable)
        table.clear()
        engagements = self.db.get_engagements()
        for eng in engagements:
            stats = self.db.get_engagement_stats(eng.id)
            table.add_row(
                str(eng.id),
                eng.name,
                eng.client or "--",
                eng.status,
                str(stats["targets"]),
                str(stats["total_findings"]),
                eng.created_at[:10] if eng.created_at else "--",
                key=str(eng.id),
            )

    def _load_engagement(self, eid: int) -> None:
        """Load an engagement and refresh all views."""
        self.current_engagement_id = eid
        eng = self.db.get_engagement(eid)
        if not eng:
            return

        stats = self.db.get_engagement_stats(eid)

        # Update header area with engagement name
        no_eng = self.query_one("#no-engagement", Static)
        no_eng.update(
            f"[bold bright_green]{eng.name}[/bold bright_green]\n"
            f"[dim]{eng.client or ''}[/dim]"
        )

        info = self.query_one("#engagement-info", Static)
        scope_display = eng.scope or "N/A"
        info.update(
            f"[bold]{eng.name}[/bold] [bright_green]|[/bright_green] "
            f"Client: {eng.client or 'N/A'} [bright_green]|[/bright_green] "
            f"Scope: {scope_display}"
        )

        # Update stat boxes
        sev = stats["findings_by_severity"]
        stat_boxes = self.query(".stat-box")
        if len(stat_boxes) >= 4:
            stat_boxes[0].update(
                f"[bold bright_green]TARGETS[/bold bright_green]\n"
                f"[bold bright_green]{stats['targets']}[/bold bright_green]"
            )
            stat_boxes[1].update(
                f"[bold bright_yellow]COMPROMISED[/bold bright_yellow]\n"
                f"[bold bright_yellow]{stats['compromised']}[/bold bright_yellow]"
            )
            stat_boxes[2].update(
                f"[bold red]CRITICAL[/bold red]\n"
                f"[bold red]{sev.get('critical', 0)}[/bold red]"
            )
            stat_boxes[3].update(
                f"[bold dark_orange]HIGH[/bold dark_orange]\n"
                f"[bold dark_orange]{sev.get('high', 0)}[/bold dark_orange]"
            )

        self._refresh_targets()
        self._refresh_findings()
        self._refresh_graph()
        self._update_status_bar()
        self.notify(f"Loaded: {eng.name}", severity="information")

    def _refresh_targets(self) -> None:
        """Refresh the targets table."""
        if not self.current_engagement_id:
            return
        table = self.query_one("#targets-table", DataTable)
        table.clear()
        targets = self.db.get_targets(self.current_engagement_id)
        for t in targets:
            ports = t.port_list
            port_str = ", ".join(str(p) for p in ports[:8])
            if len(ports) > 8:
                port_str += f" +{len(ports) - 8}"
            table.add_row(
                str(t.id),
                t.ip or "--",
                t.hostname or "--",
                t.os_guess or "--",
                _status_cell(t.status),
                port_str or "--",
                (t.notes or "--")[:30],
                key=str(t.id),
            )

    def _refresh_findings(self) -> None:
        """Refresh the findings table with Rich-styled severity cells."""
        if not self.current_engagement_id:
            return
        table = self.query_one("#findings-table", DataTable)
        table.clear()
        findings = self.db.get_findings(self.current_engagement_id)
        targets = {t.id: t for t in self.db.get_targets(self.current_engagement_id)}

        for f in findings:
            target_str = "--"
            if f.target_id and f.target_id in targets:
                t = targets[f.target_id]
                target_str = t.ip or t.hostname or "--"

            table.add_row(
                str(f.id),
                _severity_cell(f.severity),
                (f.title or "--")[:50],
                target_str,
                str(f.port) if f.port else "--",
                f.service or "--",
                f.tool_source or "--",
                f.status.replace("_", " "),
                key=str(f.id),
            )

    # ─── Actions ──────────────────────────────────────────────────────────────

    def action_new_engagement(self) -> None:
        self.push_screen(NewEngagementScreen(), callback=self._on_new_engagement)

    def _on_new_engagement(self, result: dict | None) -> None:
        if result:
            eid = self.db.create_engagement(**result)
            self._refresh_engagement_list()
            self._load_engagement(eid)
            self.notify(f"Created engagement: {result['name']}", severity="information")

    def action_add_target(self) -> None:
        if not self.current_engagement_id:
            self.notify("Load an engagement first!", severity="warning")
            return
        self.push_screen(AddTargetScreen(), callback=self._on_add_target)

    def _on_add_target(self, result: dict | None) -> None:
        if result and self.current_engagement_id:
            self.db.add_target(
                engagement_id=self.current_engagement_id,
                host=result["ip"],
                ip=result["ip"],
                hostname=result.get("hostname", ""),
                notes=result.get("notes", ""),
            )
            self._refresh_targets()
            self._refresh_engagement_list()
            self._update_status_bar()
            self.notify(f"Added target: {result['ip']}", severity="information")

    def action_import_output(self) -> None:
        if not self.current_engagement_id:
            self.notify("Load an engagement first!", severity="warning")
            return
        self.push_screen(ImportScreen(), callback=self._on_import)

    def _on_import(self, result: str | None) -> None:
        if not result or not self.current_engagement_id:
            return
        self._process_import(result)

    def _process_import(self, content: str) -> None:
        """Parse and import tool output."""
        tool = detect_tool(content)

        if tool == "nmap":
            nmap_result = parse_nmap(content)
            imported_targets = 0
            imported_findings = 0

            for host in nmap_result.hosts:
                if host.state != "up":
                    continue

                port_numbers = [p.port for p in host.ports if p.state == "open"]
                tid = self.db.add_target(
                    engagement_id=self.current_engagement_id,
                    host=host.ip or host.hostname,
                    ip=host.ip,
                    hostname=host.hostname,
                    os_guess=host.os_guess,
                    ports=json.dumps(port_numbers),
                )
                imported_targets += 1

                for port in host.ports:
                    if port.state == "open":
                        self.db.add_finding(
                            engagement_id=self.current_engagement_id,
                            target_id=tid,
                            title=f"Open port {port.port}/{port.protocol}: {port.service}",
                            severity="info",
                            description=f"Service: {port.service}\nVersion: {port.version}",
                            tool_source="nmap",
                            port=port.port,
                            service=port.service,
                        )
                        imported_findings += 1

            self._refresh_targets()
            self._refresh_findings()
            self._refresh_graph()
            self._refresh_engagement_list()
            self._update_status_bar()
            self.notify(
                f"Nmap: imported {imported_targets} hosts, {imported_findings} services",
                severity="information",
            )

        elif tool == "masscan":
            ms_result = parse_masscan(content)
            imported_targets = 0
            imported_findings = 0

            for host in ms_result.hosts:
                port_numbers = [p.port for p in host.ports if p.status == "open"]
                tid = self.db.add_target(
                    engagement_id=self.current_engagement_id,
                    host=host.ip,
                    ip=host.ip,
                    ports=json.dumps(port_numbers),
                )
                imported_targets += 1

                for port in host.ports:
                    if port.status == "open":
                        self.db.add_finding(
                            engagement_id=self.current_engagement_id,
                            target_id=tid,
                            title=f"Open port {port.port}/{port.protocol}",
                            severity="info",
                            description=(
                                f"Port: {port.port}/{port.protocol}\n"
                                f"Status: {port.status}"
                            ),
                            tool_source="masscan",
                            port=port.port,
                        )
                        imported_findings += 1

            self._refresh_targets()
            self._refresh_findings()
            self._refresh_graph()
            self._refresh_engagement_list()
            self._update_status_bar()
            self.notify(
                f"Masscan: imported {imported_targets} hosts, {imported_findings} ports",
                severity="information",
            )

        elif tool == "ffuf":
            ffuf_result = parse_ffuf(content)
            imported = 0
            for entry in ffuf_result.results:
                severity = "info"
                if entry.status in (200, 301, 302):
                    severity = "low"
                url_lower = entry.url.lower()
                if entry.status == 200 and any(
                    x in url_lower
                    for x in ["admin", "backup", "config", ".env", "debug", "phpinfo"]
                ):
                    severity = "medium"
                if entry.status == 403 and any(
                    x in url_lower for x in ["admin", "config", "server-status"]
                ):
                    severity = "low"

                self.db.add_finding(
                    engagement_id=self.current_engagement_id,
                    title=f"Fuzz hit: {entry.input_word or entry.url} [{entry.status}]",
                    severity=severity,
                    description=(
                        f"URL: {entry.url}\n"
                        f"Status: {entry.status}\n"
                        f"Size: {entry.length}\n"
                        f"Words: {entry.words}\n"
                        f"Lines: {entry.lines}"
                    ),
                    evidence=f"Redirect: {entry.redirect_location}" if entry.redirect_location else "",
                    tool_source="ffuf",
                )
                imported += 1

            self._refresh_findings()
            self._refresh_graph()
            self._refresh_engagement_list()
            self._update_status_bar()
            self.notify(f"ffuf: imported {imported} results", severity="information")

        elif tool == "nuclei":
            nuclei_result = parse_nuclei(content)
            imported = 0

            for nf in nuclei_result.findings:
                severity = nf.info.severity
                if severity not in ("critical", "high", "medium", "low", "info"):
                    severity = "info"

                cwe_str = ", ".join(nf.info.classification.cwe_ids)
                cvss_str = ""
                if nf.info.classification.cvss_score:
                    cvss_str = str(nf.info.classification.cvss_score)

                port = None
                port_match = re.search(r":(\d+)", nf.matched_at)
                if port_match:
                    try:
                        candidate = int(port_match.group(1))
                        if candidate > 0:
                            port = candidate
                    except ValueError:
                        pass

                description = nf.info.description or nf.template_id
                if nf.info.reference:
                    description += "\nReferences:\n" + "\n".join(
                        f"  - {ref}" for ref in nf.info.reference
                    )

                self.db.add_finding(
                    engagement_id=self.current_engagement_id,
                    title=f"{nf.info.name or nf.template_id}",
                    severity=severity,
                    description=description,
                    evidence=f"Matched at: {nf.matched_at}",
                    cwe=cwe_str,
                    cvss=cvss_str,
                    tool_source="nuclei",
                    port=port,
                )
                imported += 1

            self._refresh_findings()
            self._refresh_graph()
            self._refresh_engagement_list()
            self._update_status_bar()
            self.notify(f"Nuclei: imported {imported} findings", severity="information")

        elif tool == "gobuster":
            gb_result = parse_gobuster(content)
            imported = 0
            for entry in gb_result.results:
                severity = "info"
                if entry.status in (200, 301, 302):
                    severity = "low"
                if entry.status == 200 and any(
                    x in entry.url.lower()
                    for x in ["admin", "backup", "config", ".env", "debug", "phpinfo"]
                ):
                    severity = "medium"

                self.db.add_finding(
                    engagement_id=self.current_engagement_id,
                    title=f"Directory/file found: {entry.url} [{entry.status}]",
                    severity=severity,
                    description=f"URL: {entry.url}\nStatus: {entry.status}\nSize: {entry.size}",
                    evidence=f"Redirect: {entry.redirect}" if entry.redirect else "",
                    tool_source="gobuster",
                )
                imported += 1

            self._refresh_findings()
            self._refresh_graph()
            self._refresh_engagement_list()
            self._update_status_bar()
            self.notify(f"Gobuster: imported {imported} paths", severity="information")

        elif tool == "nikto":
            nikto_result = parse_nikto(content)
            imported = 0
            for finding in nikto_result.findings:
                severity = "info"
                desc_lower = finding.description.lower()
                if any(x in desc_lower for x in ["xss", "injection", "rce", "remote code"]):
                    severity = "high"
                elif any(x in desc_lower for x in ["directory listing", "backup", "default"]):
                    severity = "medium"
                elif any(x in desc_lower for x in ["header", "cookie", "version"]):
                    severity = "low"

                self.db.add_finding(
                    engagement_id=self.current_engagement_id,
                    title=f"Nikto: {finding.description[:80]}",
                    severity=severity,
                    description=finding.description,
                    evidence=f"URL: {finding.url}" if finding.url else "",
                    cwe=finding.osvdb,
                    tool_source="nikto",
                    port=nikto_result.port or None,
                )
                imported += 1

            self._refresh_findings()
            self._refresh_graph()
            self._refresh_engagement_list()
            self._update_status_bar()
            self.notify(f"Nikto: imported {imported} findings", severity="information")

        else:
            self.notify(
                "Could not detect tool format. "
                "Supports: nmap, masscan, ffuf, nuclei, gobuster, nikto",
                severity="error",
            )

    def action_show_graph(self) -> None:
        """Switch to the Graph tab."""
        tabs = self.query_one(TabbedContent)
        tabs.active = "tab-graph"
        self._refresh_graph()

    def _refresh_graph(self) -> None:
        """Refresh the ReconFlow graph widget."""
        graph = self.query_one("#recon-graph", ReconGraph)
        graph.refresh_graph(self.current_engagement_id)

    @on(ReconGraph.FindingSelected)
    def on_finding_selected(self, event: ReconGraph.FindingSelected) -> None:
        """Show finding detail modal when a finding is activated in the graph."""
        if not self.current_engagement_id:
            return
        findings = self.db.get_findings(self.current_engagement_id)
        finding = next((f for f in findings if f.id == event.finding_id), None)
        if finding:
            self.push_screen(FindingDetailScreen(finding))

    def action_gen_report(self) -> None:
        if not self.current_engagement_id:
            self.notify("Load an engagement first!", severity="warning")
            return
        report_text = generate_report(self.db, self.current_engagement_id)
        md = self.query_one("#report-md", Markdown)
        md.update(report_text)
        self.notify("Report generated!", severity="information")

    def action_show_help(self) -> None:
        """Show the help/keybindings modal."""
        self.push_screen(HelpScreen())

    # ─── Button handlers ──────────────────────────────────────────────────────

    @on(Button.Pressed, "#btn-new-eng")
    def on_new_eng_btn(self) -> None:
        self.action_new_engagement()

    @on(Button.Pressed, "#btn-import-output")
    def on_import_btn(self) -> None:
        self.action_import_output()

    @on(Button.Pressed, "#btn-add-target-tab")
    def on_add_target_btn(self) -> None:
        self.action_add_target()

    @on(Button.Pressed, "#btn-import-scan")
    def on_import_scan_btn(self) -> None:
        self.action_import_output()

    @on(Button.Pressed, "#btn-import-findings")
    def on_import_findings_btn(self) -> None:
        self.action_import_output()

    @on(Button.Pressed, "#btn-gen-report")
    def on_gen_report_btn(self) -> None:
        self.action_gen_report()

    @on(Button.Pressed, "#btn-export-report")
    def on_export_report(self) -> None:
        if not self.current_engagement_id:
            self.notify("Generate a report first!", severity="warning")
            return
        report_text = generate_report(self.db, self.current_engagement_id)
        eng = self.db.get_engagement(self.current_engagement_id)
        filename = f"pentest_report_{eng.name.replace(' ', '_').lower()}.md"
        filepath = Path.cwd() / filename
        filepath.write_text(report_text)
        self.notify(f"Report saved to: {filepath}", severity="information")

    # ─── Table row selection ──────────────────────────────────────────────────

    @on(DataTable.RowSelected, "#engagement-list")
    def on_engagement_selected(self, event: DataTable.RowSelected) -> None:
        row_key = event.row_key
        if row_key:
            try:
                eid = int(row_key.value)
                self._load_engagement(eid)
            except (ValueError, TypeError):
                pass


def main():
    """Entry point for PentBoard."""
    app = PentBoardApp()
    app.run()


if __name__ == "__main__":
    main()
