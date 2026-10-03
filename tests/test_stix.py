from collections.abc import Callable
from pathlib import Path

import pytest
from mitreattack import release_info
from mitreattack.stix20 import MitreAttackData

from mitre_navigator.stix import ActorLookupError, AttackDataset, DatasetError, DatasetRepository, download_dataset


def test_excludes_revoked_and_deprecated_objects(dataset: AttackDataset) -> None:
    assert [t.attack_id for t in dataset.techniques] == ["T1059", "T1059.001", "T1566", "T1566.002"]


def test_subtechniques_know_their_parent(dataset: AttackDataset) -> None:
    parents = {t.attack_id: t.parent_attack_id for t in dataset.techniques}

    assert parents == {"T1059": None, "T1059.001": "T1059", "T1566": None, "T1566.002": "T1566"}


@pytest.mark.parametrize("reference", ["APT28", "apt28", "Fancy Bear", "sofacy", "G0007", "g0007"])
def test_find_actor_by_name_alias_or_id(dataset: AttackDataset, reference: str) -> None:
    assert dataset.find_actor(reference).attack_id == "G0007"


def test_find_actor_ambiguous(dataset: AttackDataset) -> None:
    with pytest.raises(ActorLookupError, match="ambiguous: APT29 \\(G0016\\), Other \\(G0099\\)"):
        dataset.find_actor("Shared Alias")


def test_find_actor_unknown_suggests_close_matches(dataset: AttackDataset) -> None:
    with pytest.raises(ActorLookupError, match="not found in enterprise-attack; did you mean APT28 \\(G0007\\)"):
        dataset.find_actor("Fancy Baer")


def test_techniques_used_directly_and_via_attributed_campaigns(dataset: AttackDataset) -> None:
    used = dataset.techniques_used_by(dataset.find_actor("APT28"))

    # T1566 is only used by APT28's malware, and the revoked technique is dropped.
    assert [t.attack_id for t in used] == ["T1059.001", "T1566.002"]


def test_revoked_relationships_are_ignored(dataset: AttackDataset) -> None:
    assert dataset.techniques_used_by(dataset.find_actor("APT29")) == []


def test_repository_resolves_latest_and_loads_each_release_once(
    load_attack_data: Callable[[], MitreAttackData],
) -> None:
    calls: list[tuple[str, str]] = []

    def load(domain: str, release: str) -> MitreAttackData:
        calls.append((domain, release))
        return load_attack_data()

    repository = DatasetRepository(load=load)
    latest = repository.get("enterprise-attack", "latest")

    assert latest.attack_version == release_info.LATEST_VERSION
    assert repository.get("enterprise-attack", release_info.LATEST_VERSION) is latest
    repository.get("enterprise-attack", "15.1")
    assert calls == [("enterprise-attack", release_info.LATEST_VERSION), ("enterprise-attack", "15.1")]


def test_download_failure_is_a_dataset_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    def fail(**kwargs: object) -> None:
        raise ValueError("SHA256 hash of downloaded file does not match the known hash")

    monkeypatch.setattr("mitre_navigator.stix.download_stix", fail)

    with pytest.raises(DatasetError, match="failed to download ATT&CK ics-attack v15.1: SHA256"):
        download_dataset("ics-attack", "15.1", cache_dir=tmp_path)
