"""IPsec VPN checks.

Defaults assumed when a key is absent (FortiOS 7.x):
  phase1 type = static, dpd = on-demand, ike-version = 1, mode = main
  phase2 auto-negotiate = disable
"""

from __future__ import annotations

from ..findings import Finding, rule
from ..parser import FortiConfig

P1 = "vpn ipsec phase1-interface"
P2 = "vpn ipsec phase2-interface"

REF_S2S = ("Fortinet Community: Troubleshooting IPsec site-to-site tunnel connectivity - "
           "https://community.fortinet.com/fortigate-3/troubleshooting-tip-troubleshooting-"
           "ipsec-site-to-site-tunnel-connectivity-97517")


def _static_phase1s(cfg: FortiConfig):
    for name, p1 in cfg.entries(P1).items():
        if p1.get("type", "static") == "static":
            yield name, p1


@rule("VPN-001", "Site-to-site phase 1 without DPD on-idle")
def dpd_not_on_idle(cfg: FortiConfig) -> list[Finding]:
    out = []
    for name, p1 in _static_phase1s(cfg):
        dpd = p1.get("dpd", "on-demand")
        if dpd != "on-idle":
            out.append(Finding(
                rule_id="VPN-001",
                severity="medium",
                title="Site-to-site tunnel does not use DPD on-idle",
                obj=f"phase1-interface {name} (dpd {dpd})",
                why=("With the default on-demand DPD, a peer that reboots or loses power "
                     "may not be detected while no traffic flows. The tunnel can stay down "
                     "or keep a stale SA until someone sends traffic or resets it."),
                fix=(f'config vpn ipsec phase1-interface\n    edit "{name}"\n'
                     "        set dpd on-idle\n    next\nend"),
                refs=[REF_S2S],
            ))
    return out


@rule("VPN-002", "Site-to-site phase 2 without auto-negotiate")
def p2_no_autonegotiate(cfg: FortiConfig) -> list[Finding]:
    static = {name for name, _ in _static_phase1s(cfg)}
    out = []
    for name, p2 in cfg.entries(P2).items():
        p1name = p2.get("phase1name")
        if p1name not in static:
            continue
        if p2.get("auto-negotiate", "disable") != "enable":
            out.append(Finding(
                rule_id="VPN-002",
                severity="medium",
                title="Phase 2 selector is not auto-negotiated",
                obj=f"phase2-interface {name} (phase1 {p1name})",
                why=("This SA only comes up when traffic hits it. If the peer deletes it "
                     "during idle time, or only the peer normally initiates, the FortiGate "
                     "side can lose reachability to that selector. Each selector pair is its "
                     "own SA, so one /32 can fail while the others stay up."),
                fix=(f'config vpn ipsec phase2-interface\n    edit "{name}"\n'
                     "        set auto-negotiate enable\n    next\nend"),
                refs=[REF_S2S],
            ))
    return out


@rule("VPN-003", "Dial-up (remote access) tunnel still on IKEv1")
def dialup_ikev1(cfg: FortiConfig) -> list[Finding]:
    out = []
    for name, p1 in cfg.entries(P1).items():
        if p1.get("type", "static") != "dynamic":
            continue
        if p1.get("ike-version", "1") == "1":
            mode = p1.get("mode", "main")
            out.append(Finding(
                rule_id="VPN-003",
                severity="high",
                title="Remote access VPN uses IKEv1",
                obj=f"phase1-interface {name} (ike-version 1, mode {mode})",
                why=("FortiClient 7.4.4 and later no longer support IKEv1 for IPsec. Users "
                     "whose client updates will stop connecting. Plan a move to IKEv2 "
                     "(EAP instead of XAuth) before clients are upgraded."),
                fix=("Rebuild the tunnel as IKEv2 (new phase1/phase2, EAP authentication), "
                     "test with one user, then migrate. Do not flip ike-version in place on "
                     "a production tunnel."),
                refs=["FortiClient 7.4.4 release notes (IKEv1 removal) - docs.fortinet.com"],
            ))
    return out


@rule("VPN-004", "Many /32 phase 2 selectors on one tunnel")
def many_host_selectors(cfg: FortiConfig) -> list[Finding]:
    """Informational: several /32 selectors on one phase1 = several independent SAs."""
    per_p1: dict[str, int] = {}
    for p2 in cfg.entries(P2).values():
        p1name = p2.get("phase1name") or "?"
        dst = p2.get_list("dst-subnet")
        if len(dst) == 2 and dst[1] == "255.255.255.255":
            per_p1[p1name] = per_p1.get(p1name, 0) + 1
    out = []
    for p1name, count in per_p1.items():
        if count >= 3:
            out.append(Finding(
                rule_id="VPN-004",
                severity="info",
                title="Many single-host (/32) phase 2 selectors on one tunnel",
                obj=f"phase1-interface {p1name} ({count} host selectors)",
                why=("Valid configuration, but every selector is a separate SA. The remote "
                     "side (for example a Cisco crypto ACL) must mirror each entry exactly, "
                     "and idle SAs can expire one by one. Combine with VPN-002."),
                refs=[REF_S2S],
            ))
    return out
