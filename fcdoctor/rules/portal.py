"""Captive portal and SAML checks (wireless SSIDs and interfaces)."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from ..findings import Finding, rule
from ..parser import FortiConfig

REF_PORTAL_FLOW = ("Fortinet Community: General captive portal explanation, flow and troubleshooting - "
                   "https://community.fortinet.com/fortigate-3/troubleshooting-tip-general-captive-"
                   "portal-explanation-flow-and-troubleshooting-188409")
REF_SAML_PORTAL = ("Fortinet Docs: Captive portal authentication using SAML credentials - "
                   "https://docs.fortinet.com/document/fortiap/7.6.4/fortiwifi-and-fortiap-"
                   "configuration-guide/806280/captive-portal-authentication-using-saml-credentials")

# Hosts that phones and laptops probe to decide "is there a captive portal?"
PROBE_HOSTS = {
    "captive.apple.com",
    "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com",
    "clients3.google.com",
    "www.msftconnecttest.com",
    "msftconnecttest.com",
    "www.msftncsi.com",
    "detectportal.firefox.com",
}


def _address_hosts(cfg: FortiConfig, name: str, seen: set[str] | None = None) -> set[str]:
    """Return FQDNs (or the name itself) behind an address or address group."""
    seen = seen or set()
    if name in seen:
        return set()
    seen.add(name)
    hosts = {name.lower()}
    addr = cfg.entries("firewall address").get(name)
    if addr and addr.get("fqdn"):
        hosts.add(addr.get("fqdn").lower())
    if addr and addr.get("wildcard-fqdn"):
        hosts.add(addr.get("wildcard-fqdn").lower())
    grp = cfg.entries("firewall addrgrp").get(name)
    if grp:
        for member in grp.get_list("member"):
            hosts |= _address_hosts(cfg, member, seen)
    return hosts


@rule("PORTAL-001", "OS captive-portal probe hosts exempted from the portal")
def probe_hosts_exempted(cfg: FortiConfig) -> list[Finding]:
    out = []
    for list_name, exempt in cfg.entries("user security-exempt-list").items():
        rules = exempt.children.get("rule")
        if not rules:
            continue
        for rule_id, r in rules.entries.items():
            hits = set()
            for dst in r.get_list("dstaddr"):
                hosts = _address_hosts(cfg, dst)
                hits |= {h for h in hosts if h in PROBE_HOSTS or h.strip("*.") in PROBE_HOSTS}
            if hits:
                names = ", ".join(sorted(hits))
                out.append(Finding(
                    rule_id="PORTAL-001",
                    severity="high",
                    title="Captive-portal detection URLs are exempted",
                    obj=f'security-exempt-list "{list_name}" rule {rule_id}: {names}',
                    why=("Phones and laptops open the login page only when their probe "
                         "request gets intercepted. Exempting these hosts makes the device "
                         "think it already has internet, so the portal never pops up by "
                         "itself and users must open a browser manually."),
                    fix=(f'config user security-exempt-list\n    edit "{list_name}"\n'
                         f"        config rule\n            edit {rule_id}\n"
                         "                unselect dstaddr " +
                         " ".join(f'"{d}"' for d in r.get_list("dstaddr")
                                  if _address_hosts(cfg, d) & hits) +
                         "\n            next\n        end\n    next\nend"),
                    refs=[REF_PORTAL_FLOW],
                ))
    return out


def _is_ip_url(url: str) -> str | None:
    host = urlparse(url).hostname
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        return None


@rule("PORTAL-002", "SAML service provider URLs built on a bare IP")
def saml_on_ip(cfg: FortiConfig) -> list[Finding]:
    out = []
    for name, saml in cfg.entries("user saml").items():
        ips = set()
        for key in ("entity-id", "single-sign-on-url", "single-logout-url"):
            val = saml.get(key)
            ip = _is_ip_url(val) if val else None
            if ip:
                ips.add(ip)
        if ips:
            out.append(Finding(
                rule_id="PORTAL-002",
                severity="medium",
                title="SAML SP URLs use an IP address instead of a hostname",
                obj=f'user saml "{name}" ({", ".join(sorted(ips))})',
                why=("A certificate cannot normally match a private IP, so browsers and "
                     "the phone login window show certificate warnings or refuse the page. "
                     "Use an FQDN that resolves to the portal address and a certificate "
                     "that contains it, then update the IdP (Entra ID) with the same URLs."),
                fix=("Create a DNS record for the portal, install a certificate for it, "
                     "then set entity-id / single-sign-on-url / single-logout-url on the "
                     "FortiGate and the IdP to the FQDN."),
                refs=[REF_SAML_PORTAL],
            ))
    return out


@rule("PORTAL-003", "Captive portal SSID with a post-login redirect URL")
def redirect_url_on_portal(cfg: FortiConfig) -> list[Finding]:
    out = []
    for name, vap in cfg.entries("wireless-controller vap").items():
        if vap.get("security") != "captive-portal":
            continue
        url = vap.get("security-redirect-url")
        if url:
            out.append(Finding(
                rule_id="PORTAL-003",
                severity="low",
                title="Captive portal SSID redirects after login",
                obj=f'vap "{name}" -> {url}',
                why=("Test hint, not a documented bug: on iPhone and macOS the small login "
                     "window may stay open on the redirected page instead of closing, and "
                     "the user thinks there is no internet. If Apple users report this, try "
                     "clearing the redirect URL as a quick, reversible test."),
                fix=(f'config wireless-controller vap\n    edit "{name}"\n'
                     "        unset security-redirect-url\n    next\nend"),
                refs=[REF_SAML_PORTAL],
            ))
    return out
