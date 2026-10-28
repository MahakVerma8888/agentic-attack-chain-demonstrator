"""Parsers for Nmap XML (-oX) and Nuclei JSONL (-jsonl) output."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from .models import Finding


def parse_nmap_xml(path: str | Path) -> list[Finding]:
    """Return one finding per open port in an Nmap XML report."""
    root = ET.parse(path).getroot()
    findings: list[Finding] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        if addr_el is None:
            continue
        address = addr_el.get("addr", "unknown")
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            name = svc.get("name", "unknown") if svc is not None else "unknown"
            product = " ".join(
                p for p in (svc.get("product"), svc.get("version")) if p
            ) if svc is not None else ""
            portid = int(port.get("portid", "0"))
            proto = port.get("protocol", "tcp")
            findings.append(
                Finding(
                    host=address,
                    source="nmap",
                    title=f"Open {proto}/{portid} ({name})",
                    severity="info",
                    port=portid,
                    service=name,
                    evidence=product,
                )
            )
    return findings


def parse_nuclei_jsonl(path: str | Path) -> list[Finding]:
    """Return one finding per line of Nuclei JSONL output."""
    findings: list[Finding] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        item = json.loads(raw)
        info = item.get("info", {})
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]
        host = item.get("ip") or _host_from_url(item.get("host", "unknown"))
        findings.append(
            Finding(
                host=host,
                source="nuclei",
                title=info.get("name", item.get("template-id", "unknown")),
                severity=str(info.get("severity", "info")).lower(),
                port=_port_from_url(item.get("matched-at", "")),
                tags=[str(t).lower() for t in tags],
                cves=[str(c).upper() for c in cves],
                evidence=item.get("matched-at", ""),
            )
        )
    return findings


def _host_from_url(value: str) -> str:
    value = value.split("://", 1)[-1]
    return value.split("/", 1)[0].rsplit(":", 1)[0]


def _port_from_url(value: str) -> int | None:
    value = value.split("://", 1)[-1].split("/", 1)[0]
    if ":" in value:
        tail = value.rsplit(":", 1)[1]
        if tail.isdigit():
            return int(tail)
    return None
