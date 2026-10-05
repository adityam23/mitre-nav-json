"""The ATT&CK domains and releases known to the installed mitreattack-python library."""

from collections.abc import Iterable

from mitreattack import release_info

LATEST = "latest"
LATEST_VERSION = release_info.LATEST_VERSION
STIX_VERSION = "2.1"

# release_info keys domains by bare name ("enterprise"); bundles and layers use "enterprise-attack".
_DOMAIN_NAMES = {f"{name}-attack": name for name in release_info.STIX21}
DOMAINS = tuple(_DOMAIN_NAMES)


def domain_name(domain: str) -> str:
    """Bare domain name used by the library's download helpers (e.g. enterprise-attack -> enterprise)."""
    return _DOMAIN_NAMES[domain]


def resolve(domain: str, version: str) -> str | None:
    """The concrete release ``version`` names (``latest`` is the newest), or None if ``domain`` has no such release."""
    if version == LATEST:
        return LATEST_VERSION
    return version if version in release_info.STIX21[domain_name(domain)] else None


def unknown(domain: str, versions: Iterable[str]) -> tuple[str, ...]:
    """The ``versions`` of ``domain`` that the installed library has no release for."""
    known = release_info.STIX21[domain_name(domain)]
    return tuple(version for version in versions if version not in known)


def known_hash(domain: str, release: str) -> str:
    """SHA-256 of the official STIX bundle for ``release``, used to verify downloads."""
    return release_info.STIX21[domain_name(domain)][release]
