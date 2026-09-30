"""Routing checks."""

from __future__ import annotations

from ..findings import Finding, rule
from ..parser import FortiConfig


def _is_default(route) -> bool:
    dst = route.get_list("dst")
    return not dst or dst in (["0.0.0.0", "0.0.0.0"], ["0.0.0.0/0"])


@rule("ROUTE-001", "Several equal default routes over different WANs, no policy routes")
def ecmp_default_without_pbr(cfg: FortiConfig) -> list[Finding]:
    sdwan = cfg.section("system sdwan") or cfg.section("system virtual-wan-link")
    if sdwan and sdwan.get("status") == "enable":
        return []  # SD-WAN rules steer traffic; out of scope for this check

    groups: dict[tuple[str, str], list[str]] = {}
    for rid, r in cfg.entries("router static").items():
        if r.get("status", "enable") != "enable" or not _is_default(r):
            continue
        if r.get("blackhole") == "enable":
            continue
        key = (r.get("distance", "10"), r.get("priority", "1"))
        groups.setdefault(key, []).append(r.get("device", "?"))

    has_pbr = bool(cfg.entries("router policy"))
    out = []
    for (distance, priority), devices in groups.items():
        devs = sorted(set(devices))
        if len(devs) >= 2 and not has_pbr:
            out.append(Finding(
                rule_id="ROUTE-001",
                severity="medium",
                title="Default route is load-shared across WANs without policy routes",
                obj=f"router static: {', '.join(devs)} (distance {distance}, priority {priority})",
                why=("Traffic sourced from the FortiGate (IKE replies, ESP, SSL VPN, "
                     "management) can leave through a WAN other than the one it arrived "
                     "on. That link uses a different public IP, so the ISP or the peer "
                     "drops the reply and the VPN fails intermittently."),
                fix=("Give one WAN a lower distance or priority, or add policy routes / "
                     "SD-WAN rules so VPN traffic always uses the WAN it terminates on. "
                     "Confirm with: diagnose sniffer packet any 'udp port 500 or udp port 4500' 4 0 l"),
            ))
    return out
