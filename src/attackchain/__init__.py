"""Agentic Attack Chain Demonstrator.

A proof-of-concept that correlates Nmap and Nuclei findings into
MITRE ATT&CK-mapped attack-chain reports, with a pluggable reasoning layer
(rule-based by default, LLM-backed when you supply a completion function).
"""

__version__ = "0.1.0"
