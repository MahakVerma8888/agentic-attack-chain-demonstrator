import json
import tempfile
import unittest
from pathlib import Path

from attackchain.chains import build_chains
from attackchain.cli import analyze, main
from attackchain.mitre import map_finding
from attackchain.models import Finding
from attackchain.parsers import parse_nmap_xml, parse_nuclei_jsonl
from attackchain.reasoner import LLMReasoner, RuleBasedReasoner
from attackchain.report import to_json, to_markdown

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
NMAP = SAMPLES / "nmap_sample.xml"
NUCLEI = SAMPLES / "nuclei_sample.jsonl"


class ParserTests(unittest.TestCase):
    def test_nmap_only_open_ports(self):
        findings = parse_nmap_xml(NMAP)
        ports = {(f.host, f.port) for f in findings}
        self.assertIn(("192.0.2.10", 22), ports)
        self.assertNotIn(("192.0.2.10", 8080), ports)  # closed port ignored
        self.assertEqual(len(findings), 5)

    def test_nuclei_fields(self):
        findings = parse_nuclei_jsonl(NUCLEI)
        self.assertEqual(len(findings), 4)
        rce = findings[0]
        self.assertEqual(rce.host, "192.0.2.10")
        self.assertEqual(rce.severity, "critical")
        self.assertEqual(rce.cves, ["CVE-2021-41773"])
        self.assertEqual(rce.port, 80)


class MappingTests(unittest.TestCase):
    def test_ssh_maps_to_remote_services_and_brute_force(self):
        f = Finding(host="h", source="nmap", title="ssh", service="ssh")
        self.assertEqual({t.id for t in map_finding(f)}, {"T1133", "T1110"})

    def test_critical_rce_maps_to_initial_access_and_execution(self):
        f = Finding(host="h", source="nuclei", title="x", severity="critical", tags=["rce", "cve"])
        self.assertEqual({t.id for t in map_finding(f)}, {"T1190", "T1059"})

    def test_low_severity_cve_tag_does_not_over_map(self):
        f = Finding(host="h", source="nuclei", title="x", severity="low", tags=["cve"])
        self.assertEqual(map_finding(f), [])


class ChainTests(unittest.TestCase):
    def setUp(self):
        self.chains = analyze(str(NMAP), str(NUCLEI))

    def test_highest_risk_host_first_and_multistage(self):
        top = self.chains[0]
        self.assertEqual(top.host, "192.0.2.10")
        self.assertTrue(top.is_multi_stage)
        self.assertEqual(top.rating, "critical")

    def test_steps_follow_tactic_order(self):
        order = ["reconnaissance", "initial-access", "execution", "credential-access", "lateral-movement"]
        ranks = [order.index(s.technique.tactic) for s in self.chains[0].steps]
        self.assertEqual(ranks, sorted(ranks))

    def test_low_risk_host_is_not_multistage(self):
        low = [c for c in self.chains if c.host == "192.0.2.20"][0]
        self.assertFalse(low.is_multi_stage)
        self.assertEqual(low.rating, "low")

    def test_no_findings_no_chains(self):
        self.assertEqual(build_chains([]), [])


class ReasonerAndReportTests(unittest.TestCase):
    def test_llm_reasoner_uses_completion(self):
        chain = analyze(str(NMAP), str(NUCLEI))[0]
        text = LLMReasoner(lambda prompt: "LLM narrative").explain(chain)
        self.assertEqual(text, "LLM narrative")

    def test_llm_reasoner_falls_back_on_error(self):
        chain = analyze(str(NMAP), str(NUCLEI))[0]

        def boom(_):
            raise RuntimeError("provider down")

        self.assertEqual(LLMReasoner(boom).explain(chain), RuleBasedReasoner().explain(chain))

    def test_prompt_is_grounded_in_findings(self):
        chain = analyze(str(NMAP), str(NUCLEI))[0]
        prompt = LLMReasoner.build_prompt(chain)
        self.assertIn("T1190", prompt)
        self.assertIn("Do not invent", prompt)

    def test_markdown_and_json_reports(self):
        chains = analyze(str(NMAP), str(NUCLEI))
        md = to_markdown(chains)
        self.assertIn("# Attack Chain Report", md)
        self.assertIn("attack.mitre.org/techniques/T1190/", md)
        self.assertIn("hypothetical paths", md)
        data = json.loads(to_json(chains))
        self.assertEqual(data[0]["host"], "192.0.2.10")

    def test_cli_analyze_writes_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "r.md"
            rc = main(["analyze", "--nmap", str(NMAP), "--nuclei", str(NUCLEI), "--out", str(out)])
            self.assertEqual(rc, 0)
            self.assertTrue(out.read_text().startswith("# Attack Chain Report"))

    def test_scan_requires_authorization_flag(self):
        with self.assertRaises(SystemExit):
            main(["scan", "192.0.2.10"])


if __name__ == "__main__":
    unittest.main()
