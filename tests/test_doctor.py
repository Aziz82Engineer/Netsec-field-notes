import os
import unittest
from datetime import datetime, timezone

from fcdoctor import rules as _rules  # noqa: F401
from fcdoctor.cli import run
from fcdoctor.parser import load, parse
from fcdoctor.rules import certs

HERE = os.path.dirname(__file__)
SAMPLES = os.path.join(HERE, "..", "samples")
FIXED_NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)


def ids(findings):
    return sorted(f.rule_id for f in findings)


class ParserTests(unittest.TestCase):
    def test_nested_and_quoted(self):
        cfg = parse('''config user security-exempt-list
    edit "guest exempt"
        config rule
            edit 1
                set dstaddr "a b" "c"
            next
        end
    next
end
''')
        entry = cfg.entries("user security-exempt-list")["guest exempt"]
        rule1 = entry.children["rule"].entries["1"]
        self.assertEqual(rule1.get_list("dstaddr"), ["a b", "c"])

    def test_multiline_certificate_kept_whole(self):
        cfg = load(os.path.join(SAMPLES, "lab-problems.conf"))
        pem = cfg.entries("vpn certificate local")["portal-cert"].get("certificate")
        self.assertTrue(pem.startswith("-----BEGIN CERTIFICATE-----"))
        self.assertTrue(pem.rstrip().endswith("-----END CERTIFICATE-----"))
        # sections after the certificate still parse
        self.assertIn("RA_VPN", cfg.entries("vpn ipsec phase1-interface"))

    def test_multi_vdom_flattened(self):
        cfg = parse('''config vdom
edit root
next
end
config global
config system global
    set hostname "X"
end
end
config vdom
edit root
config vpn ipsec phase1-interface
    edit "t1"
        set remote-gw 203.0.113.1
    next
end
next
end
''')
        self.assertEqual(cfg.vdoms_seen, ["root"])
        self.assertEqual(cfg.section("system global").get("hostname"), "X")
        self.assertIn("t1", cfg.entries("vpn ipsec phase1-interface"))

    def test_header_model_and_firmware(self):
        cfg = load(os.path.join(SAMPLES, "lab-problems.conf"))
        self.assertEqual(cfg.model, "FGT50G")
        self.assertEqual(cfg.firmware, "7.6.7")


class RuleTests(unittest.TestCase):
    def setUp(self):
        self.bad = load(os.path.join(SAMPLES, "lab-problems.conf"))
        self.good = load(os.path.join(SAMPLES, "lab-clean.conf"))

    def test_problem_config_hits_every_rule(self):
        found = set(ids(run(self.bad, only={"VPN-001", "VPN-002", "VPN-003", "VPN-004",
                                               "PORTAL-001", "PORTAL-002", "PORTAL-003",
                                               "ROUTE-001"})))
        found |= set(ids(certs.expiring_certs(self.bad, now=FIXED_NOW)))
        self.assertEqual(found, {"VPN-001", "VPN-002", "VPN-003", "VPN-004", "PORTAL-001",
                                 "PORTAL-002", "PORTAL-003", "ROUTE-001", "CERT-001"})

    def test_clean_config_has_no_findings(self):
        self.assertEqual(run(self.good), [])

    def test_autonegotiate_only_flags_missing_selectors(self):
        objs = [f.obj for f in run(self.bad, only={"VPN-002"})]
        self.assertEqual(len(objs), 2)
        self.assertFalse(any("srv3" in o for o in objs))

    def test_probe_host_found_through_address_group(self):
        f = run(self.bad, only={"PORTAL-001"})[0]
        self.assertIn("connectivitycheck.gstatic.com", f.obj)
        self.assertIn('"probe-group"', f.fix)
        self.assertNotIn("login.microsoftonline.com", f.fix)

    def test_certificate_severity_by_date(self):
        soon = certs.expiring_certs(self.bad, now=FIXED_NOW)
        self.assertEqual(soon[0].severity, "medium")
        expired = certs.expiring_certs(self.bad, now=datetime(2027, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(expired[0].severity, "high")

    def test_sdwan_enabled_skips_route_check(self):
        cfg = parse('''config system sdwan
    set status enable
end
config router static
    edit 1
        set device "wan1"
    next
    edit 2
        set device "wan2"
    next
end
''')
        self.assertEqual(run(cfg, only={"ROUTE-001"}), [])


if __name__ == "__main__":
    unittest.main()
