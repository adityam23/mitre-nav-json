import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from mitreattack.stix20 import MitreAttackData

from stix import ActorLookupError, AttackDataset, DatasetError, DatasetRepository, download_dataset


def test_excludes_revoked_and_deprecated_objects(dataset: AttackDataset) -> None:
    assert [t.attack_id for t in dataset.techniques] == ["T1059", "T1059.001", "T1566", "T1566.002"]


@pytest.mark.parametrize("source_name", ["mitre-mobile-attack", "mitre-ics-attack"])
def test_reads_ids_labelled_with_pre_v12_source_names(
    stix_objects: list[dict[str, Any]], load_attack_data: Callable[[], MitreAttackData], source_name: str
) -> None:
    for obj in stix_objects:
        for reference in obj.get("external_references", []):
            reference["source_name"] = source_name

    dataset = AttackDataset(load_attack_data(), domain="mobile-attack", attack_version="11.3")

    assert [t.attack_id for t in dataset.techniques] == ["T1059", "T1059.001", "T1566", "T1566.002"]
    assert dataset.find_actor("G0007").name == "APT28"


def test_subtechniques_know_their_parent(dataset: AttackDataset) -> None:
    parents = {t.attack_id: t.parent_attack_id for t in dataset.techniques}

    assert parents == {"T1059": None, "T1059.001": "T1059", "T1566": None, "T1566.002": "T1566"}


@pytest.mark.parametrize("reference", ["APT28", "apt28", "Fancy Bear", "sofacy", "G0007", "g0007"])
def test_find_actor_by_name_alias_or_id(dataset: AttackDataset, reference: str) -> None:
    assert dataset.find_actor(reference).attack_id == "G0007"


def test_find_actor_ambiguous(dataset: AttackDataset) -> None:
    with pytest.raises(ActorLookupError, match="ambiguous: APT29 \\(G0016\\), Other \\(G0099\\)"):
        dataset.find_actor("Shared Alias")


def test_find_actor_suggests_every_actor_sharing_a_close_alias(dataset: AttackDataset) -> None:
    with pytest.raises(ActorLookupError, match="did you mean APT29 \\(G0016\\), Other \\(G0099\\)\\?"):
        dataset.find_actor("Shared Alais")


def test_find_actor_unknown_suggests_close_matches(dataset: AttackDataset) -> None:
    with pytest.raises(ActorLookupError, match="not found in enterprise-attack; did you mean APT28 \\(G0007\\)"):
        dataset.find_actor("Fancy Baer")


def test_techniques_used_directly_and_via_attributed_campaigns(dataset: AttackDataset) -> None:
    used = dataset.techniques_used_by(dataset.find_actor("APT28"))

    # T1566 is only used by APT28's malware, and the revoked technique is dropped.
    assert [t.attack_id for t in used] == ["T1059.001", "T1566.002"]


def test_revoked_relationships_are_ignored(dataset: AttackDataset) -> None:
    assert dataset.techniques_used_by(dataset.find_actor("APT29")) == []


def test_repository_loads_each_release_once(load_attack_data: Callable[[], MitreAttackData]) -> None:
    calls: list[tuple[str, str]] = []

    def load(domain: str, release: str) -> MitreAttackData:
        calls.append((domain, release))
        return load_attack_data()

    repository = DatasetRepository(load=load)
    first = repository.get("enterprise-attack", "16.1")

    assert first.attack_version == "16.1"
    assert repository.get("enterprise-attack", "16.1") is first
    repository.get("enterprise-attack", "15.1")
    repository.get("ics-attack", "15.1")
    assert calls == [("enterprise-attack", "16.1"), ("enterprise-attack", "15.1"), ("ics-attack", "15.1")]


def test_download_failure_is_a_dataset_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fail(**kwargs: object) -> None:
        raise ValueError("SHA256 hash of downloaded file does not match the known hash")

    monkeypatch.setattr("stix.download_stix", fail)

    with pytest.raises(DatasetError, match="failed to download ATT&CK ics-attack v15.1: SHA256"):
        download_dataset("ics-attack", "15.1", cache_dir=tmp_path)


def test_invalid_bundle_is_a_dataset_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Mirrors enterprise 16.0, whose "HomeLand Justice" campaign was last seen before it was first seen.
    campaign = {
        "type": "campaign",
        "spec_version": "2.1",
        "id": "campaign--7e21077d-2589-43a7-a5f9-490061289526",
        "created": "2024-01-01T00:00:00.000Z",
        "modified": "2024-01-01T00:00:00.000Z",
        "name": "HomeLand Justice",
        "first_seen": "2021-05-01T04:00:00.000Z",
        "last_seen": "2002-09-01T04:00:00.000Z",
    }
    bundle = tmp_path / "v16.0" / "enterprise-attack.json"
    bundle.parent.mkdir()
    bundle.write_text(json.dumps({"type": "bundle", "id": "bundle--1", "objects": [campaign]}))
    monkeypatch.setattr("stix.download_stix", lambda **kwargs: None)

    with pytest.raises(DatasetError, match="enterprise-attack v16.0 bundle is invalid STIX: .*'last_seen'"):
        download_dataset("enterprise-attack", "16.0", cache_dir=tmp_path)
