"""Heuristic mapping from scanner findings to MITRE ATT&CK techniques.

The mapping is intentionally small, transparent and easy to extend: each rule
is a plain function that inspects a ``Finding`` and returns the techniques it
suggests. It is a *triage aid*, not a substitute for analyst judgement.
"""

from __future__ import annotations

from typing import Callable, Iterable

from .models import Finding, Technique

# --- Technique catalogue (subset of ATT&CK Enterprise) -----------------------
T1190 = Technique("T1190", "Exploit Public-Facing Application", "initial-access")
T1133 = Technique("T1133", "External Remote Services", "initial-access")
T1078_001 = Technique("T1078.001", "Valid Accounts: Default Accounts", "initial-access")
T1059 = Technique("T1059", "Command and Scripting Interpreter", "execution")
T1552_001 = Technique("T1552.001", "Unsecured Credentials: Credentials In Files", "credential-access")
T1110 = Technique("T1110", "Brute Force", "credential-access")
T1021_002 = Technique("T1021.002", "Remote Services: SMB/Windows Admin Shares", "lateral-movement")
T1592_002 = Technique("T1592.002", "Gather Victim Host Information: Software", "reconnaissance")

TACTIC_ORDER = [
    "reconnaissance",
    "initial-access",
    "execution",
    "credential-access",
    "lateral-movement",
]

REMOTE_ACCESS_SERVICES = {"ssh", "telnet", "ms-wbt-server", "rdp", "vnc", "winrm"}
SMB_SERVICES = {"microsoft-ds", "netbios-ssn", "smb"}
DATABASE_SERVICES = {"mysql", "postgresql", "ms-sql-s", "mongodb", "redis", "oracle"}

Rule = Callable[[Finding], Iterable[Technique]]


def _nmap_services(f: Finding) -> Iterable[Technique]:
    if f.source != "nmap" or not f.service:
        return
    if f.service in REMOTE_ACCESS_SERVICES:
        yield T1133
        yield T1110  # exposed login surface invites credential guessing
    elif f.service in SMB_SERVICES:
        yield T1021_002
    elif f.service in DATABASE_SERVICES:
        yield T1190


def _nuclei_exploitable(f: Finding) -> Iterable[Technique]:
    if f.source != "nuclei":
        return
    exploit_tags = {"rce", "sqli", "lfi", "ssrf", "deserialization", "cve"}
    if f.severity in {"high", "critical"} and (set(f.tags) & exploit_tags or f.cves):
        yield T1190
    if "rce" in f.tags:
        yield T1059


def _nuclei_default_creds(f: Finding) -> Iterable[Technique]:
    if f.source == "nuclei" and {"default-login", "default-credentials"} & set(f.tags):
        yield T1078_001


def _nuclei_exposure(f: Finding) -> Iterable[Technique]:
    if f.source == "nuclei" and {"exposure", "token", "config", "backup", "git", "env"} & set(f.tags):
        yield T1552_001


def _nuclei_fingerprint(f: Finding) -> Iterable[Technique]:
    if f.source == "nuclei" and f.severity == "info" and {"tech", "detect"} & set(f.tags):
        yield T1592_002


RULES: list[Rule] = [
    _nmap_services,
    _nuclei_exploitable,
    _nuclei_default_creds,
    _nuclei_exposure,
    _nuclei_fingerprint,
]


def map_finding(finding: Finding) -> list[Technique]:
    """Return the de-duplicated techniques suggested for one finding."""
    seen: dict[str, Technique] = {}
    for rule in RULES:
        for technique in rule(finding):
            seen.setdefault(technique.id, technique)
    return list(seen.values())


REMEDIATION = {
    "T1190": "Patch or virtually patch the affected application; restrict exposure behind a WAF/VPN.",
    "T1133": "Restrict remote-access services to a VPN or allow-list; enforce MFA.",
    "T1078.001": "Change all default credentials and disable unused default accounts.",
    "T1059": "Apply vendor patches for code-execution flaws; run services with least privilege.",
    "T1552.001": "Remove secrets from web-accessible files; rotate any exposed credentials.",
    "T1110": "Enforce account lockout, rate limiting and MFA on login surfaces.",
    "T1021.002": "Disable SMB where unneeded; block 445/139 at the perimeter; enforce SMB signing.",
    "T1592.002": "Reduce version banners and technology disclosure where practical.",
}
