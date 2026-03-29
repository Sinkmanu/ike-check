"""CLI entry point for ike-check."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from . import __version__
from .report import report_console, report_json, report_text
from .scanner import ScanConfig, Scanner


def _check_root() -> bool:
    """Check if running with sufficient privileges for raw sockets."""
    return os.geteuid() == 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ike-check",
        description="IKE Cipher Suite Scanner - enumerate supported cipher suites from an IKE peer",
    )
    parser.add_argument(
        "target",
        help="Target IP address or hostname",
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"ike-check {__version__}",
    )
    parser.add_argument(
        "--ike-version",
        choices=["ikev1", "ikev2", "both"],
        default="both",
        help="IKE version to probe (default: both)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=500,
        help="Destination port (default: 500)",
    )
    parser.add_argument(
        "--nat-traversal",
        action="store_true",
        help="Also probe on port 4500 (NAT-Traversal)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=5.0,
        help="Timeout per probe in seconds (default: 5)",
    )
    parser.add_argument(
        "-r", "--retries",
        type=int,
        default=2,
        help="Retries per probe on timeout (default: 2)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between probes in seconds (default: 0.5)",
    )
    parser.add_argument(
        "--aggressive",
        action="store_true",
        help="Also probe IKEv1 Aggressive Mode",
    )
    parser.add_argument(
        "--phase2-infer",
        action="store_true",
        help="Infer Phase 2 support from Phase 1 results",
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int,
        default=1,
        help="Concurrent probes (default: 1, be careful with rate limiting)",
    )
    parser.add_argument(
        "-o", "--output",
        choices=["console", "json", "text"],
        default="console",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "--output-file",
        type=str,
        default=None,
        help="Write output to file (for json/text formats)",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan with reduced cipher suite catalog",
    )
    parser.add_argument(
        "--weak-only",
        action="store_true",
        help="Only probe weak and insecure cipher suites (INSECURE + WEAK security level)",
    )
    parser.add_argument(
        "--no-dh-sweep",
        action="store_true",
        help="Skip DH group sweep and test all groups (slower but more thorough)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show rejected and timed-out proposals too",
    )
    parser.add_argument(
        "-s", "--source-ip",
        type=str,
        default=None,
        help="Source IP address (for multi-homed hosts)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    console = Console(stderr=True)

    # Check privileges
    if not _check_root():
        console.print(
            "[bold yellow]WARNING:[/] Not running as root. "
            "Raw sockets may fail. Consider running with sudo.",
        )

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Build scan config
    config = ScanConfig(
        target_ip=args.target,
        port=args.port,
        timeout=args.timeout,
        retries=args.retries,
        delay=args.delay,
        quick=args.quick,
        weak_only=args.weak_only,
        source_ip=args.source_ip,
        ike_version=args.ike_version,
        aggressive=args.aggressive,
        nat_traversal=args.nat_traversal,
        dh_sweep=not args.no_dh_sweep,
        verbose=args.verbose,
    )

    scanner = Scanner(config)

    # Progress tracking
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("({task.completed}/{task.total})"),
        console=console,
    )

    task_ids: dict[str, int] = {}

    def progress_callback(phase: str, current: int, total: int) -> None:
        labels = {
            "ikev2_dh_sweep": "IKEv2 DH sweep",
            "ikev2": "IKEv2 ciphers",
            "ikev1_main": "IKEv1 Main Mode",
            "ikev1_aggressive": "IKEv1 Aggressive",
        }
        label = labels.get(phase, phase)
        if phase not in task_ids:
            task_ids[phase] = progress.add_task(label, total=total)
        progress.update(task_ids[phase], completed=current)

    with progress:
        results = scanner.scan(progress_callback=progress_callback)

    # Output
    if args.output == "console":
        report_console(results, verbose=args.verbose)
    elif args.output == "json":
        if args.output_file:
            with open(args.output_file, "w") as f:
                report_json(results, fp=f)
            console.print(f"JSON output written to {args.output_file}")
        else:
            print(report_json(results))
    elif args.output == "text":
        if args.output_file:
            with open(args.output_file, "w") as f:
                report_text(results, fp=f)
            console.print(f"Text output written to {args.output_file}")
        else:
            print(report_text(results))

    return 0


if __name__ == "__main__":
    sys.exit(main())
