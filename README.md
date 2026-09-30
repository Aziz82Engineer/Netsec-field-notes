# FortiGate Config Doctor

Offline checks for FortiGate backup files. Point it at a `.conf` and it lists the misconfigurations that keep turning into support tickets, explains each one in plain language, and gives the CLI to fix it.

It never connects to a firewall. It only reads the backup file you give it.

```
$ python doctor.py samples/lab-problems.conf
FortiGate Config Doctor v0.1.0
File:     samples/lab-problems.conf
Device:   FGT50G  FortiOS 7.6.7
Summary:  high=2  medium=6  low=1  info=1

[HIGH] PORTAL-001  Captive-portal detection URLs are exempted
      Object: security-exempt-list "guest-exempt" rule 1: captive.apple.com, connectivitycheck.gstatic.com
      Phones and laptops open the login page only when their probe request gets intercepted.
      Exempting these hosts makes the device think it already has internet, so the portal
      never pops up by itself and users must open a browser manually.
      Fix (review before applying):
        config user security-exempt-list
            edit "guest-exempt"
        ...
```

## Why this exists

Most L1 firewall tickets are not new problems. They are the same handful of settings, found again by hand in a 70,000-line config. Each rule here comes from a real case: a site-to-site tunnel that stayed down after a power cut, a remote-access VPN that broke when FortiClient updated, a guest Wi-Fi portal that never popped up on phones.

## Quick start

Requires Python 3.9+. The only dependency is `cryptography`, used for the certificate check (the other rules run without it).

```bash
git clone https://github.com/Aziz82Engineer/fortigate-config-doctor.git
cd fortigate-config-doctor
pip install -r requirements.txt
python doctor.py path/to/backup.conf
```

Options:

| Option | What it does |
|---|---|
| `--min-severity medium` | Hide low and info findings |
| `--rule VPN-002` | Run one rule (repeatable) |
| `--json` | Machine-readable output |
| `--list-rules` | Show all checks |

Exit code is `1` when any HIGH finding exists and `2` on a read error, so it can gate a CI job or a pre-change review.

## Checks

| ID | Severity | What it catches |
|---|---|---|
| VPN-001 | medium | Site-to-site phase 1 without `dpd on-idle` |
| VPN-002 | medium | Site-to-site phase 2 without `auto-negotiate enable` |
| VPN-003 | high | Remote-access (dial-up) tunnel still on IKEv1, which FortiClient 7.4.4+ no longer supports |
| VPN-004 | info | Many /32 phase 2 selectors on one tunnel (each is its own SA; peer ACL must mirror them) |
| PORTAL-001 | high | Apple / Android / Windows captive-portal probe hosts in a security exempt list, including via address groups |
| PORTAL-002 | medium | SAML SP URLs (entity-id, SSO, SLO) built on a bare IP instead of an FQDN |
| PORTAL-003 | low | Captive-portal SSID with a post-login redirect URL (test hint for Apple login-window issues) |
| CERT-001 | high / medium | Local certificate expired or expiring within 60 days |
| ROUTE-001 | medium | Equal default routes over several WANs with no policy routes or SD-WAN (asymmetric VPN replies) |

Findings are hints for an engineer to review, not automatic fixes. Always check the fix against the device and a maintenance window before applying it.

## Project layout

```
fortigate-config-doctor/
├── doctor.py              # entry point
├── fcdoctor/
│   ├── parser.py          # FortiOS .conf -> nested sections/entries (handles VDOMs, multi-line certs)
│   ├── findings.py        # Finding model and @rule registry
│   ├── cli.py             # text / JSON report
│   └── rules/             # one module per area: vpn, portal, certs, routing
├── runbooks/              # CLI debug sequences to confirm a finding on the live device
├── samples/               # fake lab configs (no customer data)
└── tests/
```

## Adding a rule

Create a function in the right module under `fcdoctor/rules/` and decorate it:

```python
@rule("VPN-005", "Short description for --list-rules")
def my_check(cfg):
    out = []
    for name, p1 in cfg.entries("vpn ipsec phase1-interface").items():
        if p1.get("some-key", "default") == "bad":
            out.append(Finding(rule_id="VPN-005", severity="medium", title="...",
                               obj=f"phase1-interface {name}", why="...", fix="..."))
    return out
```

Then add a case to `samples/lab-problems.conf` and a test in `tests/`. Run the tests with:

```bash
python -m unittest discover -s tests -t .
```

## Data safety

Never commit real customer configs, serial numbers, public IPs, usernames or certificates. The files in `samples/` were written by hand and use documentation address ranges (RFC 5737). Build new samples from a lab FortiGate-VM, not from tickets.

## Roadmap

- SSL VPN checks (weak TLS settings, portal on default port)
- Admin access on WAN interfaces, trusted hosts missing
- Firmware notes per model (for example 30G/31G upgrade path and memory)
- HTML report for sharing with customers

## License

MIT
