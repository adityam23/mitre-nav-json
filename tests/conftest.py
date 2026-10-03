from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from mitreattack.stix20 import MitreAttackData
from stix2 import MemoryStore

from mitre_navigator.stix import AttackDataset, DatasetRepository

_TIMESTAMP = "2024-01-01T00:00:00.000Z"


def _id(stix_type: str, name: str) -> str:
    return f"{stix_type}--{uuid.uuid5(uuid.NAMESPACE_URL, name)}"


def _object(stix_type: str, stix_id: str, **properties: Any) -> dict[str, Any]:
    return {
        "type": stix_type,
        "spec_version": "2.1",
        "id": stix_id,
        "created": _TIMESTAMP,
        "modified": _TIMESTAMP,
        **properties,
    }


def _ref(attack_id: str) -> list[dict[str, str]]:
    return [{"source_name": "mitre-attack", "external_id": attack_id}]


def _technique(stix_id: str, attack_id: str, name: str, **extra: Any) -> dict[str, Any]:
    return _object(
        "attack-pattern",
        stix_id,
        name=name,
        external_references=_ref(attack_id),
        x_mitre_is_subtechnique="." in attack_id,
        **extra,
    )


def _group(stix_id: str, attack_id: str, name: str, aliases: list[str]) -> dict[str, Any]:
    return _object("intrusion-set", stix_id, name=name, aliases=aliases, external_references=_ref(attack_id))


def _rel(kind: str, source: str, target: str, *, revoked: bool = False) -> dict[str, Any]:
    # ATT&CK always sets "revoked" on relationships, and the library only follows those set to false.
    return _object(
        "relationship",
        _id("relationship", f"{source} {kind} {target}"),
        relationship_type=kind,
        source_ref=source,
        target_ref=target,
        revoked=revoked,
    )


PHISHING = _id("attack-pattern", "phishing")
SPEARPHISHING_LINK = _id("attack-pattern", "spearphishing-link")
POWERSHELL = _id("attack-pattern", "powershell")
SCRIPTING = _id("attack-pattern", "scripting")
REVOKED = _id("attack-pattern", "revoked")
DEPRECATED = _id("attack-pattern", "deprecated")
APT28 = _id("intrusion-set", "apt28")
APT29 = _id("intrusion-set", "apt29")
OTHER = _id("intrusion-set", "other")
CAMPAIGN = _id("campaign", "c0001")
MALWARE = _id("malware", "x-agent")


@pytest.fixture
def stix_objects() -> list[dict[str, Any]]:
    return [
        _technique(PHISHING, "T1566", "Phishing"),
        _technique(SPEARPHISHING_LINK, "T1566.002", "Spearphishing Link"),
        _technique(SCRIPTING, "T1059", "Command and Scripting Interpreter"),
        _technique(POWERSHELL, "T1059.001", "PowerShell"),
        _technique(REVOKED, "T9999", "Revoked", revoked=True),
        _technique(DEPRECATED, "T9998", "Deprecated", x_mitre_deprecated=True),
        _group(APT28, "G0007", "APT28", ["APT28", "Fancy Bear", "Sofacy"]),
        _group(APT29, "G0016", "APT29", ["APT29", "Cozy Bear", "Shared Alias"]),
        _group(OTHER, "G0099", "Other", ["Shared Alias"]),
        _object("campaign", CAMPAIGN, name="C0001", external_references=_ref("C0001")),
        _object("malware", MALWARE, name="X-Agent", is_family=True, external_references=_ref("S0161")),
        _rel("subtechnique-of", SPEARPHISHING_LINK, PHISHING),
        _rel("subtechnique-of", POWERSHELL, SCRIPTING),
        _rel("uses", APT28, SPEARPHISHING_LINK),
        _rel("uses", APT28, REVOKED),
        _rel("uses", CAMPAIGN, POWERSHELL),
        _rel("attributed-to", CAMPAIGN, APT28),
        _rel("uses", MALWARE, PHISHING),
        _rel("uses", APT28, MALWARE),
        _rel("uses", APT29, PHISHING, revoked=True),
    ]


@pytest.fixture
def load_attack_data(stix_objects: list[dict[str, Any]]) -> Callable[[], MitreAttackData]:
    return lambda: MitreAttackData(src=MemoryStore(stix_data=stix_objects, allow_custom=True))


@pytest.fixture
def dataset(load_attack_data: Callable[[], MitreAttackData]) -> AttackDataset:
    return AttackDataset(load_attack_data(), domain="enterprise-attack", attack_version="16.1")


@pytest.fixture
def repository(load_attack_data: Callable[[], MitreAttackData]) -> DatasetRepository:
    return DatasetRepository(load=lambda domain, release: load_attack_data())
