"""Command line entry point.

    python doctor.py backup.conf
    python doctor.py backup.conf --json
    python doctor.py backup.conf --min-severity medium
    python doctor.py --list-rules
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap

from . import __version__
from . import rules as _rules  # noqa: F401  (registers checks)
from .findings import RULES, SEVERITY_ORDER, Finding
from .parser import FortiConfig, load

ICON = {"high": "[HIGH]", "medium": "[MED] ", "low": "[LOW] ", "info": "[INFO]"}


def run(cfg: FortiConfig, only: set[str] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for rule_id, _desc, fn in RULES:
        if only and rule_id not in only:
            continue
        findings.extend(fn(cfg))
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule_id, f.obj))
    return findings


def _indent(text: str, pad: str = "      ", wrap: bool = False) -> str:
    if wrap:
        return textwrap.fill(text, width=92, initial_indent=pad, subsequent_indent=pad)
    return "\n".join(pad + line for line in text.splitlines())


def render_text(cfg: FortiConfig, findings: list[Finding], source: str) -> str:
    lines = [f"FortiGate Config Doctor v{__version__}", f"File:     {source}"]
    if cfg.model:
        lines.append(f"Device:   {cfg.model}  FortiOS {cfg.firmware or '?'}")
    if cfg.vdoms_seen:
        lines.append(f"VDOMs:    {', '.join(cfg.vdoms_seen)} (checked as one tree)")
    counts = {s: sum(f.severity == s for f in findings) for s in SEVERITY_ORDER}
    lines.append("Summary:  " + "  ".join(f"{s}={n}" for s, n in counts.items()))
    lines.append("")
    if not findings:
        lines.append("No findings. Nothing matched the current rules.")
    for f in findings:
        lines.append(f"{ICON[f.severity]} {f.rule_id}  {f.title}")
        lines.append(f"      Object: {f.obj}")
        lines.append(_indent(f.why, wrap=True))
        if f.fix:
            lines.append("      Fix (review before applying):")
            lines.append(_indent(f.fix, "        "))
        for ref in f.refs:
            lines.append(f"      Ref: {ref}")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Offline checks for FortiGate backup (.conf) files.")
    ap.add_argument("config", nargs="?", help="FortiGate backup file (.conf)")
    ap.add_argument("--json", action="store_true", help="output JSON instead of text")
    ap.add_argument("--min-severity", choices=list(SEVERITY_ORDER), default="info",
                    help="hide findings below this level")
    ap.add_argument("--rule", action="append", metavar="ID", help="run only this rule (repeatable)")
    ap.add_argument("--list-rules", action="store_true", help="list available rules and exit")
    args = ap.parse_args(argv)

    if args.list_rules:
        for rule_id, desc, _ in RULES:
            print(f"{rule_id:<11} {desc}")
        return 0
    if not args.config:
        ap.error("a config file is required")

    try:
        cfg = load(args.config)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not cfg.sections:
        print("error: no FortiOS config sections found - is this a FortiGate backup?", file=sys.stderr)
        return 2

    limit = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in run(cfg, set(args.rule) if args.rule else None)
                if SEVERITY_ORDER[f.severity] <= limit]

    if args.json:
        print(json.dumps({
            "file": args.config,
            "model": cfg.model,
            "firmware": cfg.firmware,
            "findings": [f.to_dict() for f in findings],
        }, indent=2))
    else:
        print(render_text(cfg, findings, args.config))

    # Exit 1 when anything high is present, so it can gate a CI job.
    return 1 if any(f.severity == "high" for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
