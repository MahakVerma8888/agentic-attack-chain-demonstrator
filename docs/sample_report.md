# Attack Chain Report

_Generated 2026-10-27 07:02 UTC_

> **Note:** chains are *hypothetical paths derived from scanner findings* and ATT&CK heuristics. They are triage aids for defenders, not proof of exploitability.

## Summary

| Host | Rating | Score | Tactics | Steps |
|---|---|---|---|---|
| 192.0.2.10 | CRITICAL | 38 | initial-access → execution → credential-access → lateral-movement | 7 |
| 192.0.2.20 | LOW | 0 | reconnaissance | 1 |

## Host 192.0.2.10 - CRITICAL (score 38)

Host 192.0.2.10 exposes weaknesses across 4 tactics, so an adversary could plausibly combine them as follows:

1. **Initial Access** via Valid Accounts: Default Accounts (T1078.001), supported by: Admin Panel Default Credentials.
2. **Initial Access** via External Remote Services (T1133), supported by: Open tcp/22 (ssh).
3. **Initial Access** via Exploit Public-Facing Application (T1190), supported by: Apache HTTP Server Path Traversal and RCE, Open tcp/3306 (mysql).
4. **Execution** via Command and Scripting Interpreter (T1059), supported by: Apache HTTP Server Path Traversal and RCE.
5. **Credential Access** via Brute Force (T1110), supported by: Open tcp/22 (ssh).
6. **Credential Access** via Unsecured Credentials: Credentials In Files (T1552.001), supported by: Exposed .env Configuration File.
7. **Lateral Movement** via Remote Services: SMB/Windows Admin Shares (T1021.002), supported by: Open tcp/445 (microsoft-ds).

| # | Tactic | Technique | Evidence |
|---|---|---|---|
| 1 | initial-access | [T1078.001](https://attack.mitre.org/techniques/T1078/001/) Valid Accounts: Default Accounts | Admin Panel Default Credentials |
| 2 | initial-access | [T1133](https://attack.mitre.org/techniques/T1133/) External Remote Services | Open tcp/22 (ssh) |
| 3 | initial-access | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | Apache HTTP Server Path Traversal and RCE<br>Open tcp/3306 (mysql) |
| 4 | execution | [T1059](https://attack.mitre.org/techniques/T1059/) Command and Scripting Interpreter | Apache HTTP Server Path Traversal and RCE |
| 5 | credential-access | [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force | Open tcp/22 (ssh) |
| 6 | credential-access | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) Unsecured Credentials: Credentials In Files | Exposed .env Configuration File |
| 7 | lateral-movement | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) Remote Services: SMB/Windows Admin Shares | Open tcp/445 (microsoft-ds) |

**Recommended mitigations**

- Change all default credentials and disable unused default accounts.
- Restrict remote-access services to a VPN or allow-list; enforce MFA.
- Patch or virtually patch the affected application; restrict exposure behind a WAF/VPN.
- Apply vendor patches for code-execution flaws; run services with least privilege.
- Enforce account lockout, rate limiting and MFA on login surfaces.
- Remove secrets from web-accessible files; rotate any exposed credentials.
- Disable SMB where unneeded; block 445/139 at the perimeter; enforce SMB signing.

## Host 192.0.2.20 - LOW (score 0)

Host 192.0.2.20 shows an isolated weakness (single tactic):

1. **Reconnaissance** via Gather Victim Host Information: Software (T1592.002), supported by: nginx Version Detection.

| # | Tactic | Technique | Evidence |
|---|---|---|---|
| 1 | reconnaissance | [T1592.002](https://attack.mitre.org/techniques/T1592/002/) Gather Victim Host Information: Software | nginx Version Detection |

**Recommended mitigations**

- Reduce version banners and technology disclosure where practical.
