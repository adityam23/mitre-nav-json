"""Load MITRE ATT&CK STIX releases via mitreattack-python and index the objects needed for layers."""

from __future__ import annotations

import difflib
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pooch
from mitreattack.download_stix import download_stix
from mitreattack.stix20 import MitreAttackData

from . import releases

# CI points MITRE_NAVIGATOR_CACHE_DIR at a directory it persists between runs.
DEFAULT_CACHE_DIR = Path(os.environ.get("MITRE_NAVIGATOR_CACHE_DIR") or pooch.os_cache("mitre-navigator"))

DatasetLoader = Callable[[str, str], MitreAttackData]


class DatasetError(RuntimeError):
    """Raised when a STIX dataset cannot be obtained."""


class ActorLookupError(LookupError):
    """Raised when a threat actor reference cannot be resolved to exactly one group."""


@dataclass(frozen=True)
class Technique:
    stix_id: str
    attack_id: str
    name: str
    parent_attack_id: str | None = None

    @property
    def is_subtechnique(self) -> bool:
        return self.parent_attack_id is not None


@dataclass(frozen=True)
class ThreatActor:
    stix_id: str
    attack_id: str
    name: str
    aliases: tuple[str, ...]


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
    # Same layout download_stix writes to.
    return MitreAttackData(stix_filepath=str(cache_dir / f"v{release}" / f"{domain}.json"))


class AttackDataset:
    """Active techniques and groups of one ATT&CK domain release, and which techniques each group uses."""

    def __init__(self, data: MitreAttackData, *, domain: str, attack_version: str) -> None:
        self.domain = domain
        self.attack_version = attack_version
        self._data = data

        parents = data.get_all_parent_techniques_of_all_subtechniques()
        self.techniques = sorted(
            (
                Technique(
                    stix_id=obj.id,
                    attack_id=data.get_attack_id(obj.id),
                    name=obj.name,
                    parent_attack_id=next(
                        (data.get_attack_id(entry["object"].id) for entry in parents.get(obj.id, ())), None
                    ),
                )
                for obj in data.get_techniques(remove_revoked_deprecated=True)
            ),
            key=lambda t: t.attack_id,
        )
        self.actors = sorted(
            (
                ThreatActor(
                    stix_id=obj.id,
                    attack_id=data.get_attack_id(obj.id),
                    name=obj.name,
                    aliases=tuple(obj.get("aliases", ())),
                )
                for obj in data.get_groups(remove_revoked_deprecated=True)
            ),
            key=lambda a: a.attack_id,
        )
        self._techniques_by_stix_id = {t.stix_id: t for t in self.techniques}

    def find_actor(self, reference: str) -> ThreatActor:
        """Resolve a name, alias or ATT&CK group ID (case-insensitive) to exactly one actor."""
        needle = reference.casefold()
        matches = [actor for actor in self.actors if needle in _actor_keys(actor)]
        if len(matches) == 1:
            return matches[0]
        if matches:
            candidates = ", ".join(f"{a.name} ({a.attack_id})" for a in matches)
            raise ActorLookupError(f"threat actor '{reference}' is ambiguous: {candidates}")

        known = {key: actor for actor in self.actors for key in _actor_keys(actor)}
        suggestions = difflib.get_close_matches(needle, known, n=3, cutoff=0.6)
        hint = ""
        if suggestions:
            hint = "; did you mean " + ", ".join(
                sorted({f"{known[s].name} ({known[s].attack_id})" for s in suggestions})
            ) + "?"
        raise ActorLookupError(f"threat actor '{reference}' not found in {self.domain}{hint}")

    def techniques_used_by(self, actor: ThreatActor) -> list[Technique]:
        """Techniques the group uses directly or through campaigns attributed to it."""
        stix_ids = {entry["object"].id for entry in self._data.get_techniques_used_by_group(actor.stix_id)}
        return sorted(
            (self._techniques_by_stix_id[s] for s in stix_ids if s in self._techniques_by_stix_id),
            key=lambda t: t.attack_id,
        )


class DatasetRepository:
    """Loads datasets on demand and caches them so each domain/release is loaded once per run."""

    def __init__(self, load: DatasetLoader = download_dataset) -> None:
        self._load = load
        self._cache: dict[tuple[str, str], AttackDataset] = {}

    def get(self, domain: str, version: str) -> AttackDataset:
        release = releases.resolve(version)
        key = (domain, release)
        if key not in self._cache:
            self._cache[key] = AttackDataset(self._load(domain, release), domain=domain, attack_version=release)
        return self._cache[key]


def _actor_keys(actor: ThreatActor) -> set[str]:
    return {key.casefold() for key in (actor.attack_id, actor.name, *actor.aliases)}
