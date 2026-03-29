"""Report generation: rich console, JSON, and plain text output."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import TextIO

from rich.console import Console
from rich.table import Table
from rich.text import Text

from . import __version__
from .classifier import (
    IKEv1ProposalResult,
    IKEv2ProposalResult,
    ProbeStatus,
    classify_suite_level,
)
from .scanner import ScanResults
from .transforms import SecurityLevel


def _format_duration(seconds: float) -> str:
    """Format duration as human readable string."""
    m, s = divmod(int(seconds), 60)
    if m > 0:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def _security_text(level: SecurityLevel) -> Text:
    """Create a rich Text with colored security label."""
    return Text(f"[{level.label}]", style=f"bold {level.color}")


def _status_text(status: ProbeStatus) -> str:
    """Format probe status for display."""
    return {
        ProbeStatus.ACCEPTED: "ACCEPTED",
        ProbeStatus.REJECTED: "REJECTED",
        ProbeStatus.TIMEOUT: "TIMEOUT",
        ProbeStatus.INVALID_KE: "INVALID_KE",
    }[status]


# ---------------------------------------------------------------------------
# Console (rich) output
# ---------------------------------------------------------------------------

def report_console(results: ScanResults, verbose: bool = False) -> None:
    """Print scan results to console using rich."""
    console = Console()

    # Header
    console.print()
    console.print(f" [bold cyan]ipsec-check v{__version__}[/] - IPSec Cipher Suite Scanner")
    console.print()
    console.print(f" Target: [bold]{results.target_ip}:{results.port}[/]")

    version_label = {
        "ikev2": "IKEv2",
        "ikev1": "IKEv1",
        "both": "IKEv1 + IKEv2",
    }.get(results.ike_version, results.ike_version)
    console.print(f" IKE Version: {version_label}")

    start_dt = datetime.fromtimestamp(results.start_time, tz=timezone.utc)
    console.print(f" Scan started: {start_dt:%Y-%m-%d %H:%M:%S UTC}")
    console.print()

    # IKEv2 results
    if results.ikev2_results:
        _print_ikev2_table(console, results.ikev2_results, verbose)

    # IKEv1 results
    if results.ikev1_results:
        _print_ikev1_table(console, results.ikev1_results, verbose)

    # Summary
    _print_summary(console, results)


def _print_ikev2_table(
    console: Console,
    results: list[IKEv2ProposalResult],
    verbose: bool,
) -> None:
    """Print IKEv2 results table."""
    console.rule("[bold]Phase 1 - IKE SA (IKE_SA_INIT) - IKEv2", style="cyan")
    console.print()

    table = Table(show_header=True, header_style="bold", padding=(0, 1))
    table.add_column("Encryption", min_width=16)
    table.add_column("Integrity", min_width=16)
    table.add_column("PRF", min_width=16)
    table.add_column("DH Group", min_width=14)
    table.add_column("Status", min_width=12)

    # Show accepted first, then optionally rejected
    accepted = [r for r in results if r.status == ProbeStatus.ACCEPTED]
    rejected = [r for r in results if r.status == ProbeStatus.REJECTED]
    timeouts = [r for r in results if r.status == ProbeStatus.TIMEOUT]
    invalid_ke = [r for r in results if r.status == ProbeStatus.INVALID_KE]

    for r in accepted:
        level = r.security_level
        status_txt = Text(f"ACCEPTED  ", style="bold green")
        status_txt.append_text(_security_text(level))
        table.add_row(
            r.encr_name,
            r.integ_name,
            r.prf_name,
            r.dh_name,
            status_txt,
        )

    if verbose:
        for r in rejected:
            table.add_row(
                r.encr_name, r.integ_name, r.prf_name, r.dh_name,
                Text("REJECTED", style="dim"),
            )
        for r in timeouts:
            table.add_row(
                r.encr_name, r.integ_name, r.prf_name, r.dh_name,
                Text("TIMEOUT", style="dim yellow"),
            )
        for r in invalid_ke:
            extra = f" (try {r.suggested_dh.name})" if r.suggested_dh else ""
            table.add_row(
                r.encr_name, r.integ_name, r.prf_name, r.dh_name,
                Text(f"INVALID_KE{extra}", style="dim yellow"),
            )

    console.print(table)
    console.print()


def _print_ikev1_table(
    console: Console,
    results: list[IKEv1ProposalResult],
    verbose: bool,
) -> None:
    """Print IKEv1 results table."""
    # Group by mode
    for mode in ("main", "aggressive"):
        mode_results = [r for r in results if r.mode == mode]
        if not mode_results:
            continue

        mode_label = "Main Mode" if mode == "main" else "Aggressive Mode"
        console.rule(f"[bold]Phase 1 - IKE SA - IKEv1 ({mode_label})", style="cyan")
        console.print()

        table = Table(show_header=True, header_style="bold", padding=(0, 1))
        table.add_column("Encryption", min_width=16)
        table.add_column("Hash", min_width=14)
        table.add_column("Auth", min_width=12)
        table.add_column("DH Group", min_width=14)
        table.add_column("Status", min_width=12)

        accepted = [r for r in mode_results if r.status == ProbeStatus.ACCEPTED]
        rejected = [r for r in mode_results if r.status == ProbeStatus.REJECTED]

        for r in accepted:
            from .transforms import IKEV1_AUTH_CATALOG
            level = r.security_level
            status_txt = Text("ACCEPTED  ", style="bold green")
            status_txt.append_text(_security_text(level))
            auth_info = IKEV1_AUTH_CATALOG.get(r.auth_method)
            auth_name = auth_info.name if auth_info else str(r.auth_method)
            table.add_row(
                r.encr_name,
                r.hash_name,
                auth_name,
                r.dh_name,
                status_txt,
            )

        if verbose:
            for r in rejected:
                from .transforms import IKEV1_AUTH_CATALOG
                auth_info = IKEV1_AUTH_CATALOG.get(r.auth_method)
                auth_name = auth_info.name if auth_info else str(r.auth_method)
                table.add_row(
                    r.encr_name, r.hash_name, auth_name, r.dh_name,
                    Text("REJECTED", style="dim"),
                )

        console.print(table)
        console.print()


def _print_summary(console: Console, results: ScanResults) -> None:
    """Print summary section."""
    console.rule("[bold]Summary", style="cyan")
    console.print()

    all_results = results.ikev2_results + results.ikev1_results
    accepted = [r for r in all_results if r.status == ProbeStatus.ACCEPTED]
    rejected = [r for r in all_results if r.status == ProbeStatus.REJECTED]
    timeouts = [r for r in all_results if r.status == ProbeStatus.TIMEOUT]

    console.print(f" Total proposals tested: {results.total_probes}")
    console.print(
        f" Accepted: [green]{len(accepted)}[/]  |  "
        f"Rejected: {len(rejected)}  |  "
        f"Timeout: {len(timeouts)}"
    )
    console.print()

    levels = classify_suite_level(all_results)
    for level in (SecurityLevel.STRONG, SecurityLevel.OK, SecurityLevel.WEAK, SecurityLevel.INSECURE):
        count = levels[level]
        if count > 0:
            console.print(f" [{level.color}]{level.label:10s}[/]: {count} suites")

    console.print()

    if levels[SecurityLevel.INSECURE] > 0:
        console.print(
            " [bold red]WARNING: Peer accepts INSECURE cipher suites[/]",
        )
    if levels[SecurityLevel.WEAK] > 0:
        console.print(
            " [bold yellow]NOTICE: Peer accepts WEAK cipher suites[/]",
        )

    duration = _format_duration(results.duration_seconds)
    console.print(f"\n Scan completed in {duration}")
    console.print()


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def _result_to_dict(r: IKEv2ProposalResult | IKEv1ProposalResult) -> dict:
    """Convert a proposal result to a JSON-serializable dict."""
    if isinstance(r, IKEv2ProposalResult):
        return {
            "version": "ikev2",
            "encryption": r.encr_name,
            "integrity": r.integ_name,
            "prf": r.prf_name,
            "dh_group": r.dh_name,
            "status": _status_text(r.status),
            "security_level": r.security_level.label if r.status == ProbeStatus.ACCEPTED else None,
        }
    else:
        from .transforms import IKEV1_AUTH_CATALOG
        auth_info = IKEV1_AUTH_CATALOG.get(r.auth_method)
        return {
            "version": "ikev1",
            "mode": r.mode,
            "encryption": r.encr_name,
            "hash": r.hash_name,
            "auth_method": auth_info.name if auth_info else str(r.auth_method),
            "dh_group": r.dh_name,
            "status": _status_text(r.status),
            "security_level": r.security_level.label if r.status == ProbeStatus.ACCEPTED else None,
        }


def report_json(results: ScanResults, fp: TextIO | None = None) -> str:
    """Generate JSON report. If fp is provided, writes to it and returns empty string."""
    all_results = results.ikev2_results + results.ikev1_results
    accepted = [r for r in all_results if r.status == ProbeStatus.ACCEPTED]

    data = {
        "tool": "ipsec-check",
        "version": __version__,
        "target": results.target_ip,
        "port": results.port,
        "ike_version": results.ike_version,
        "scan_start": datetime.fromtimestamp(results.start_time, tz=timezone.utc).isoformat(),
        "scan_end": datetime.fromtimestamp(results.end_time, tz=timezone.utc).isoformat(),
        "duration_seconds": round(results.duration_seconds, 2),
        "total_probes": results.total_probes,
        "accepted_count": len(accepted),
        "results": [_result_to_dict(r) for r in all_results],
        "summary": {
            level.label: classify_suite_level(all_results)[level]
            for level in SecurityLevel
        },
    }

    json_str = json.dumps(data, indent=2)
    if fp:
        fp.write(json_str)
        return ""
    return json_str


# ---------------------------------------------------------------------------
# Plain text output
# ---------------------------------------------------------------------------

def report_text(results: ScanResults, fp: TextIO | None = None) -> str:
    """Generate plain text report."""
    lines: list[str] = []

    lines.append(f"ipsec-check v{__version__} - IPSec Cipher Suite Scanner")
    lines.append(f"Target: {results.target_ip}:{results.port}")
    lines.append(f"IKE Version: {results.ike_version}")
    lines.append("")

    all_results = results.ikev2_results + results.ikev1_results
    accepted = [r for r in all_results if r.status == ProbeStatus.ACCEPTED]

    if accepted:
        lines.append("ACCEPTED CIPHER SUITES:")
        lines.append("-" * 80)
        for r in accepted:
            if isinstance(r, IKEv2ProposalResult):
                lines.append(
                    f"  IKEv2: {r.encr_name:20s} {r.integ_name:18s} "
                    f"{r.prf_name:16s} {r.dh_name:14s} [{r.security_level.label}]"
                )
            else:
                from .transforms import IKEV1_AUTH_CATALOG
                auth_info = IKEV1_AUTH_CATALOG.get(r.auth_method)
                auth_name = auth_info.name if auth_info else str(r.auth_method)
                lines.append(
                    f"  IKEv1({r.mode:10s}): {r.encr_name:20s} {r.hash_name:14s} "
                    f"{auth_name:10s} {r.dh_name:14s} [{r.security_level.label}]"
                )

    lines.append("")
    lines.append(f"Total probes: {results.total_probes}")
    lines.append(f"Accepted: {len(accepted)}")
    lines.append(f"Duration: {_format_duration(results.duration_seconds)}")

    text = "\n".join(lines)
    if fp:
        fp.write(text)
        return ""
    return text
