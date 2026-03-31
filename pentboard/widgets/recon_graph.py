"""ReconFlow - Interactive network graph visualization widget for PentBoard.

Renders an ASCII tree graph of hosts, services, and findings from the
current engagement. Nodes are navigable with arrow keys; pressing Enter
on a finding shows its details.
"""

from dataclasses import dataclass
from typing import Optional

from rich.text import Text
from textual import on
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.widgets import OptionList, Static
from textual.widgets.option_list import Option

from pentboard.models.database import Database, Finding, Target


# ── Severity display config ─────────────────────────────────────────────────

SEVERITY_STYLES: dict[str, str] = {
    "critical": "bold white on dark_red",
    "high": "bold white on red3",
    "medium": "bold black on yellow",
    "low": "bold white on dodger_blue2",
    "info": "dim white on grey37",
}

SEVERITY_TAGS: dict[str, str] = {
    "critical": " CRIT ",
    "high": " HIGH ",
    "medium": " MED  ",
    "low": " LOW  ",
    "info": " INFO ",
}

# ── Rich markup styles ──────────────────────────────────────────────────────

HOST_STYLE = "bold bright_white"
HOSTNAME_STYLE = "cyan"
OS_STYLE = "dim"
CONNECTOR_STYLE = "bright_cyan"
PORT_STYLE = "bold green"
SERVICE_STYLE = "bright_green"
VERSION_STYLE = "dim"
FINDING_TITLE_STYLE = "bold"


# ── Data structures ─────────────────────────────────────────────────────────

@dataclass
class GraphNodeData:
    """Metadata attached to each graph option for interaction handling."""

    node_type: str  # "host", "service", "finding", "empty"
    target_id: Optional[int] = None
    finding_id: Optional[int] = None
    port: Optional[int] = None
    severity: str = ""


# ── Widget ──────────────────────────────────────────────────────────────────

class ReconGraph(Vertical):
    """Interactive network graph visualization widget.

    Displays targets, services, and findings as an ASCII tree.
    Navigate with arrow keys, press Enter on a finding for details.
    """

    DEFAULT_CSS = """
    ReconGraph {
        height: 100%;
    }
    ReconGraph #graph-list {
        height: 1fr;
    }
    ReconGraph #graph-legend {
        height: 3;
        padding: 0 2;
        color: $text-muted;
    }
    ReconGraph #graph-title {
        height: 3;
        padding: 0 2;
        text-align: center;
        text-style: bold;
        color: $accent;
    }
    """

    class FindingSelected(Message):
        """Posted when a finding node is activated (Enter pressed)."""

        def __init__(self, finding_id: int) -> None:
            """Initialize with the selected finding's database ID."""
            super().__init__()
            self.finding_id = finding_id

    def __init__(
        self,
        db: Database,
        engagement_id: Optional[int] = None,
        *,
        name: str | None = None,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        """Initialize ReconGraph widget.

        Args:
            db: Database instance for querying targets/findings.
            engagement_id: Current engagement ID (can be set later).
            name: Widget name.
            id: Widget DOM id.
            classes: Widget CSS classes.
        """
        super().__init__(name=name, id=id, classes=classes)
        self.db = db
        self.engagement_id = engagement_id
        self._node_map: dict[str, GraphNodeData] = {}

    def compose(self) -> ComposeResult:
        """Build the widget tree."""
        yield Static(
            "[bold bright_cyan]ReconFlow[/bold bright_cyan]"
            " [dim]-- Network Graph[/dim]",
            id="graph-title",
        )
        yield OptionList(id="graph-list")
        yield Static(self._build_legend(), id="graph-legend")

    def _build_legend(self) -> Text:
        """Build the severity color legend bar."""
        legend = Text()
        legend.append("  ")
        for sev in ("critical", "high", "medium", "low", "info"):
            legend.append(SEVERITY_TAGS[sev], style=SEVERITY_STYLES[sev])
            legend.append(" ")
        legend.append("  ", style="dim")
        legend.append("↑↓", style="bold bright_white")
        legend.append(" Navigate  ", style="dim")
        legend.append("Enter", style="bold bright_white")
        legend.append(" View details", style="dim")
        return legend

    # ── Public API ───────────────────────────────────────────────────────────

    def refresh_graph(self, engagement_id: Optional[int] = None) -> None:
        """Rebuild the graph from the current database state.

        Args:
            engagement_id: If provided, switch to this engagement first.
        """
        if engagement_id is not None:
            self.engagement_id = engagement_id

        option_list = self.query_one("#graph-list", OptionList)
        option_list.clear_options()
        self._node_map.clear()

        if not self.engagement_id:
            self._add_empty_state(
                option_list, "Load an engagement to view the network graph"
            )
            return

        targets = self.db.get_targets(self.engagement_id)
        findings = self.db.get_findings(self.engagement_id)

        if not targets:
            self._add_empty_state(
                option_list, "Import scan data to build graph"
            )
            return

        self._build_graph(option_list, targets, findings)

    # ── Graph construction ───────────────────────────────────────────────────

    def _add_empty_state(self, option_list: OptionList, message: str) -> None:
        """Show a placeholder message when there is nothing to graph."""
        text = Text()
        text.append("\n  ")
        text.append(message, style="dim italic")
        text.append("\n")
        opt_id = "empty-0"
        option_list.add_option(Option(text, id=opt_id))
        self._node_map[opt_id] = GraphNodeData(node_type="empty")

    def _build_graph(
        self,
        option_list: OptionList,
        targets: list[Target],
        findings: list[Finding],
    ) -> None:
        """Build the full ASCII tree graph from targets and findings."""
        # Group findings by target_id
        findings_by_target: dict[Optional[int], list[Finding]] = {}
        for f in findings:
            findings_by_target.setdefault(f.target_id, []).append(f)

        for t_idx, target in enumerate(targets):
            self._add_host_node(option_list, target)
            target_findings = findings_by_target.get(target.id, [])
            self._add_service_tree(option_list, target, target_findings)

            # Visual spacer between hosts
            if t_idx < len(targets) - 1:
                spacer_id = f"spacer-{t_idx}"
                option_list.add_option(Option(Text(" "), id=spacer_id))
                self._node_map[spacer_id] = GraphNodeData(node_type="empty")

    def _add_host_node(
        self, option_list: OptionList, target: Target
    ) -> None:
        """Render a host header line."""
        text = Text()
        text.append("  ╭─ ", style=CONNECTOR_STYLE)
        text.append(
            target.ip or target.hostname or target.host, style=HOST_STYLE
        )
        if target.hostname and target.ip:
            text.append(f" ({target.hostname})", style=HOSTNAME_STYLE)
        if target.os_guess:
            text.append(f"  {target.os_guess}", style=OS_STYLE)

        opt_id = f"host-{target.id}"
        option_list.add_option(Option(text, id=opt_id))
        self._node_map[opt_id] = GraphNodeData(
            node_type="host", target_id=target.id
        )

    def _add_service_tree(
        self,
        option_list: OptionList,
        target: Target,
        target_findings: list[Finding],
    ) -> None:
        """Render service and finding nodes under a host."""
        # Group findings by port
        by_port: dict[int, list[Finding]] = {}
        for f in target_findings:
            by_port.setdefault(f.port or 0, []).append(f)

        ports = sorted(by_port.keys())

        if not ports:
            text = Text()
            text.append("  ╰─ ", style=CONNECTOR_STYLE)
            text.append("(no services discovered)", style="dim italic")
            opt_id = f"no-svc-{target.id}"
            option_list.add_option(Option(text, id=opt_id))
            self._node_map[opt_id] = GraphNodeData(
                node_type="empty", target_id=target.id
            )
            return

        for p_idx, port in enumerate(ports):
            is_last_port = p_idx == len(ports) - 1
            port_findings = by_port[port]

            # Split info-level service detections from real vuln findings
            service_finding: Optional[Finding] = None
            vuln_findings: list[Finding] = []
            for f in port_findings:
                if f.severity == "info" and service_finding is None:
                    service_finding = f
                else:
                    vuln_findings.append(f)

            # Service line
            connector = "\u2570" if is_last_port else "\u251c"  # ╰ or ├
            text = Text()
            text.append(f"  {connector}\u2500\u2500 ", style=CONNECTOR_STYLE)
            if port:
                text.append(f":{port}", style=PORT_STYLE)
            else:
                text.append("general", style="dim")

            if service_finding:
                svc_name = service_finding.service or ""
                if svc_name:
                    text.append(f" {svc_name}", style=SERVICE_STYLE)
                version = _extract_version(service_finding)
                if version:
                    text.append(f"  {version}", style=VERSION_STYLE)

            opt_id = f"svc-{target.id}-{port}"
            option_list.add_option(Option(text, id=opt_id))
            self._node_map[opt_id] = GraphNodeData(
                node_type="service",
                target_id=target.id,
                finding_id=service_finding.id if service_finding else None,
                port=port if port else None,
            )

            # Vulnerability findings nested under this service
            for v_idx, vf in enumerate(vuln_findings):
                is_last_vuln = v_idx == len(vuln_findings) - 1
                vert = " " if is_last_port else "\u2502"  # │
                v_conn = "\u2570" if is_last_vuln else "\u251c"  # ╰ or ├

                text = Text()
                text.append(
                    f"  {vert}   {v_conn}\u2500\u2500 ", style=CONNECTOR_STYLE
                )
                sev_style = SEVERITY_STYLES.get(vf.severity, "")
                sev_tag = SEVERITY_TAGS.get(
                    vf.severity, f" {vf.severity.upper()} "
                )
                text.append(sev_tag, style=sev_style)
                text.append(f" {vf.title}", style=FINDING_TITLE_STYLE)

                opt_id = f"finding-{vf.id}"
                option_list.add_option(Option(text, id=opt_id))
                self._node_map[opt_id] = GraphNodeData(
                    node_type="finding",
                    target_id=vf.target_id,
                    finding_id=vf.id,
                    port=vf.port,
                    severity=vf.severity,
                )

    # ── Event handlers ───────────────────────────────────────────────────────

    @on(OptionList.OptionSelected, "#graph-list")
    def _on_option_selected(
        self, event: OptionList.OptionSelected
    ) -> None:
        """Handle Enter press on a graph node."""
        opt_id = str(event.option.id) if event.option.id else None
        if not opt_id or opt_id not in self._node_map:
            return
        node = self._node_map[opt_id]
        if node.node_type == "finding" and node.finding_id is not None:
            self.post_message(self.FindingSelected(node.finding_id))


# ── Helpers ─────────────────────────────────────────────────────────────────

def _extract_version(finding: Finding) -> str:
    """Pull the version string out of a finding's description field."""
    for line in (finding.description or "").split("\n"):
        if line.startswith("Version:"):
            ver = line.split(":", 1)[1].strip()
            if ver:
                return ver
    return ""
