"""Command-line interface: ``python -m attackchain``."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

from .chains import build_chains
from .parsers import parse_nmap_xml, parse_nuclei_jsonl
from .reasoner import RuleBasedReasoner
from .report import to_json, to_markdown


def analyze(nmap: str | None, nuclei: str | None, reasoner=None):
    findings = []
    if nmap:
        findings += parse_nmap_xml(nmap)
    if nuclei:
        findings += parse_nuclei_jsonl(nuclei)
    chains = build_chains(findings)
    reasoner = reasoner or RuleBasedReasoner()
    for chain in chains:
        chain.narrative = reasoner.explain(chain)
    return chains


def _scan(target: str, workdir: Path) -> tuple[str, str]:
    """Run Nmap and Nuclei against a target you are authorised to test."""
    for tool in ("nmap", "nuclei"):
        if shutil.which(tool) is None:
            sys.exit(f"error: '{tool}' not found on PATH")
    workdir.mkdir(parents=True, exist_ok=True)
    nmap_out, nuclei_out = workdir / "nmap.xml", workdir / "nuclei.jsonl"
    subprocess.run(["nmap", "-sV", "-oX", str(nmap_out), target], check=True)
    subprocess.run(["nuclei", "-u", target, "-jsonl", "-o", str(nuclei_out)], check=True)
    return str(nmap_out), str(nuclei_out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attackchain",
        description="Correlate Nmap + Nuclei findings into MITRE ATT&CK-mapped attack chains.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyse existing scan output (recommended)")
    a.add_argument("--nmap", help="Nmap XML file (-oX)")
    a.add_argument("--nuclei", help="Nuclei JSONL file (-jsonl)")
    a.add_argument("--out", default="report.md", help="Markdown report path")
    a.add_argument("--json", dest="json_out", help="optional JSON report path")

    s = sub.add_parser("scan", help="run nmap + nuclei, then analyse (authorised targets only)")
    s.add_argument("target")
    s.add_argument("--authorized", action="store_true", help="confirm you have written permission to test the target")
    s.add_argument("--workdir", default="scan-output")
    s.add_argument("--out", default="report.md")

    args = parser.parse_args(argv)

    if args.command == "scan":
        if not args.authorized:
            parser.error("refusing to scan: pass --authorized to confirm you have permission to test this target")
        nmap_file, nuclei_file = _scan(args.target, Path(args.workdir))
        chains = analyze(nmap_file, nuclei_file)
        json_out = None
    else:
        if not (args.nmap or args.nuclei):
            parser.error("provide at least one of --nmap / --nuclei")
        chains = analyze(args.nmap, args.nuclei)
        json_out = args.json_out

    Path(args.out).write_text(to_markdown(chains), encoding="utf-8")
    if json_out:
        Path(json_out).write_text(to_json(chains), encoding="utf-8")
    print(f"Wrote {args.out} ({len(chains)} host chain(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
