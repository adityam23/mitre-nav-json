"""Load MITRE ATT&CK STIX releases via mitreattack-python and index the objects needed for layers."""

import difflib
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pooch
from mitreattack.download_stix import download_stix
from mitreattack.stix20 import MitreAttackData

import releases
from errors import RequestError

# CI points MITRE_NAVIGATOR_CACHE_DIR at a directory it persists between runs.
DEFAULT_CACHE_DIR = Path(os.environ.get("MITRE_NAVIGATOR_CACHE_DIR") or pooch.os_cache("mitre-navigator"))

DatasetLoader = Callable[[str, str], MitreAttackData]

# Before ATT&CK v12, mobile and ICS IDs were labelled with their own source name instead of "mitre-attack".
_ATTACK_ID_SOURCES = frozenset({"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"})


class DatasetError(RequestError):
    """Raised when a STIX dataset cannot be obtained."""


class ActorLookupError(RequestError):
    """Raised when a threat actor reference cannot be resolved to exactly one group."""


@dataclass(frozen=True)
class Technique:
    stix_id: str
    attack_id: str
    name: str

    @property
    def parent_attack_id(self) -> str | None:
        """ATT&CK numbers sub-techniques under their parent: T1566.002 belongs to T1566."""
        parent, dot, _ = self.attack_id.partition(".")
        return parent if dot else None

    @property
    def is_subtechnique(self) -> bool:
        return self.parent_attack_id is not None


@dataclass(frozen=True)
class ThreatActor:
    stix_id: str
    attack_id: str
    name: str
    aliases: tuple[str, ...]

    @property
    def label(self) -> str:
        return f"{self.name} ({self.attack_id})"


def download_dataset(domain: str, release: str, *, cache_dir: Path = DEFAULT_CACHE_DIR) -> MitreAttackData:
    """Fetch (or reuse from ``cache_dir``) the hash-verified STIX bundle of one ATT&CK release."""
    try:
        download_stix(
            stix_version=releases.STIX_VERSION,
            domain=releases.domain_name(domain),
            download_dir=str(cache_dir),
            release=release,
            known_hash=releases.known_hash(domain, release),
        )
    except (OSError, ValueError) as exc:
        raise DatasetError(f"failed to download ATT&CK {domain} v{release}: {exc}") from exc
    try:
        # Same layout download_stix writes to.
        return MitreAttackData(stix_filepath=str(cache_dir / f"v{release}" / f"{domain}.json"))
    except ValueError as exc:
        # Some official bundles break STIX rules (e.g. enterprise 16.0 has a campaign last seen before first seen).
        raise DatasetError(f"MITRE's ATT&CK {domain} v{release} bundle is invalid STIX: {exc}") from exc


class AttackDataset:
    """Active techniques and groups of one ATT&CK domain release, and which techniques each group uses."""

    def __init__(self, data: MitreAttackData, *, domain: str, attack_version: str) -> None:
        self.domain = domain
        self.attack_version = attack_version
        self._data = data

        self.techniques = sorted(
            (
                Technique(stix_id=obj.id, attack_id=_attack_id(obj), name=obj.name)
                for obj in data.get_techniques(remove_revoked_deprecated=True)
            ),
            key=lambda t: t.attack_id,
        )
        actors = sorted(
            (
                ThreatActor(
                    stix_id=obj.id,
                    attack_id=_attack_id(obj),
                    name=obj.name,
                    aliases=tuple(obj.get("aliases", ())),
                )
                for obj in data.get_groups(remove_revoked_deprecated=True)
            ),
            key=lambda a: a.attack_id,
        )
        # Every case-insensitive name, alias and group ID -> the actors known by it (aliases can be shared).
        self._actors_by_key: dict[str, list[ThreatActor]] = {}
        for actor in actors:
            for key in {key.casefold() for key in (actor.attack_id, actor.name, *actor.aliases)}:
                self._actors_by_key.setdefault(key, []).append(actor)

    def find_actor(self, reference: str) -> ThreatActor:
        """Resolve a name, alias or ATT&CK group ID (case-insensitive) to exactly one actor."""
        needle = reference.casefold()
        matches = self._actors_by_key.get(needle, [])
        if len(matches) == 1:
            return matches[0]
        if matches:
            raise ActorLookupError(f"threat actor '{reference}' is ambiguous: {', '.join(a.label for a in matches)}")

        suggestions = difflib.get_close_matches(needle, self._actors_by_key, n=3, cutoff=0.6)
        hint = ""
        if suggestions:
            labels = sorted({actor.label for key in suggestions for actor in self._actors_by_key[key]})
            hint = f"; did you mean {', '.join(labels)}?"
        raise ActorLookupError(f"threat actor '{reference}' not found in {self.domain}{hint}")

    def techniques_used_by(self, actor: ThreatActor) -> list[Technique]:
        """Techniques the group uses directly or through campaigns attributed to it."""
        used = {entry["object"].id for entry in self._data.get_techniques_used_by_group(actor.stix_id)}
        return [technique for technique in self.techniques if technique.stix_id in used]


class DatasetRepository:
    """Loads datasets on demand and caches them so each domain/release is loaded once per run."""

    def __init__(self, load: DatasetLoader = download_dataset) -> None:
        self._load = load
        self._cache: dict[tuple[str, str], AttackDataset] = {}

    def get(self, domain: str, release: str) -> AttackDataset:
        key = (domain, release)
        if key not in self._cache:
            self._cache[key] = AttackDataset(self._load(domain, release), domain=domain, attack_version=release)
        return self._cache[key]


def _attack_id(obj: Any) -> str | None:
    """The object's ATT&CK ID, read like ``MitreAttackData.get_attack_id`` but also from pre-v12 mobile/ICS bundles."""
    references = obj.get("external_references", ())
    if references and references[0].get("source_name") in _ATTACK_ID_SOURCES:
        return references[0].get("external_id")
    return None
