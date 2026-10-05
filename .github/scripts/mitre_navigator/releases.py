"""The ATT&CK domains and releases known to the installed mitreattack-python library."""

from mitreattack import release_info

LATEST = "latest"
STIX_VERSION = "2.1"

# release_info keys domains by bare name ("enterprise"); bundles and layers use "enterprise-attack".
_DOMAIN_NAMES = {f"{name}-attack": name for name in release_info.STIX21}
DOMAINS = tuple(_DOMAIN_NAMES)


def domain_name(domain: str) -> str:
    """Bare domain name used by the library's download helpers (e.g. enterprise-attack -> enterprise)."""
    return _DOMAIN_NAMES[domain]


def is_known(domain: str, version: str) -> bool:
    return version == LATEST or version in release_info.STIX21[domain_name(domain)]


def resolve(version: str) -> str:
    """Turn ``latest`` into the concrete newest release; other versions are returned unchanged."""
    return release_info.LATEST_VERSION if version == LATEST else version


def known_hash(domain: str, release: str) -> str:
    """SHA-256 of the official STIX bundle for ``release``, used to verify downloads."""
    return release_info.STIX21[domain_name(domain)][release]
