"""Certificate expiry checks for local certificates stored in the backup."""

from __future__ import annotations

from datetime import datetime, timezone

from ..findings import Finding, rule
from ..parser import FortiConfig

WARN_DAYS = 60

try:
    from cryptography import x509
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False


def _not_after(pem: str):
    cert = x509.load_pem_x509_certificate(pem.encode())
    try:
        return cert.not_valid_after_utc
    except AttributeError:  # older cryptography
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _cert_entries(cfg: FortiConfig):
    for section in ("vpn certificate local", "certificate local"):
        for name, entry in cfg.entries(section).items():
            pem = entry.get("certificate")
            if pem and "BEGIN CERTIFICATE" in pem:
                yield name, pem


@rule("CERT-001", f"Local certificate expired or expiring within {WARN_DAYS} days")
def expiring_certs(cfg: FortiConfig, now: datetime | None = None) -> list[Finding]:
    if not HAVE_CRYPTO:
        return [Finding(
            rule_id="CERT-001", severity="info",
            title="Certificate check skipped",
            obj="-", why="Install the 'cryptography' package to check certificate expiry.",
        )]
    now = now or datetime.now(timezone.utc)
    out = []
    for name, pem in _cert_entries(cfg):
        if name.startswith("Fortinet_"):
            continue  # factory certificates, managed by Fortinet
        try:
            expiry = _not_after(pem)
        except Exception:  # noqa: BLE001 - malformed PEM in a backup is not fatal
            continue
        days = (expiry - now).days
        if days < 0:
            sev, title = "high", "Local certificate has expired"
        elif days <= WARN_DAYS:
            sev, title = "medium", "Local certificate expires soon"
        else:
            continue
        out.append(Finding(
            rule_id="CERT-001",
            severity=sev,
            title=title,
            obj=f'certificate "{name}" (expires {expiry:%Y-%m-%d}, {days} days)',
            why=("Anything using it (SSL VPN, captive portal, admin GUI, SAML) will show "
                 "certificate errors or fail once it expires. Renew and import it before "
                 "the date, then switch every place that references it."),
            fix="Renew the certificate, import it under System > Certificates, then update references.",
        ))
    return out
