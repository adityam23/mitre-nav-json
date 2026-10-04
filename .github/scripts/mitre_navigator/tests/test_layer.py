from collections.abc import Callable

from mitreattack.navlayers.core.versions import defaults as navlayers_defaults
from mitreattack.stix20 import MitreAttackData

from layer import ACTOR_TECHNIQUE_COLOR, build_layer
from stix import AttackDataset


def _by_id(layer: dict) -> dict[str, dict]:
    return {t["techniqueID"]: t for t in layer["techniques"]}


def test_layer_without_actor_lists_all_techniques_uncolored(dataset: AttackDataset) -> None:
    layer = build_layer(dataset, [])

    assert layer["name"] == "enterprise-attack v16.1"
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"] == {
        "attack": "16",
        "navigator": navlayers_defaults["navigator"],
        "layer": navlayers_defaults["layer"],
    }
    assert "legendItems" not in layer
    assert layer["layout"]["showID"] is False
    assert sorted(_by_id(layer)) == ["T1059", "T1059.001", "T1566", "T1566.002"]
    assert all("color" not in t for t in layer["techniques"])


def test_actor_techniques_are_red(dataset: AttackDataset) -> None:
    apt28 = dataset.find_actor("APT28")

    techniques = _by_id(build_layer(dataset, [apt28]))

    for attack_id in ("T1059.001", "T1566.002"):
        assert techniques[attack_id]["color"] == ACTOR_TECHNIQUE_COLOR == "#ff0000"
        assert techniques[attack_id]["score"] == 1
        assert techniques[attack_id]["comment"] == "Used by: APT28"
    assert "color" not in techniques["T1566"]


def test_parent_expands_when_subtechnique_is_highlighted(dataset: AttackDataset) -> None:
    techniques = _by_id(build_layer(dataset, [dataset.find_actor("APT28")]))

    assert techniques["T1566"]["showSubtechniques"] is True
    assert techniques["T1059"]["showSubtechniques"] is True
    assert techniques["T1059.001"]["showSubtechniques"] is False


def test_custom_name_legend_and_metadata(dataset: AttackDataset) -> None:
    apt28 = dataset.find_actor("APT28")

    layer = build_layer(dataset, [apt28], name="My layer")

    assert layer["name"] == "My layer"
    assert layer["legendItems"] == [{"label": "Used by APT28", "color": "#ff0000"}]
    assert layer["metadata"] == [{"name": "threat_actor", "value": "APT28 (G0007)"}]


def test_score_counts_actors_using_the_technique(
    add_relationship: Callable[[str, str, str], None], load_attack_data: Callable[[], MitreAttackData]
) -> None:
    add_relationship("uses", "G0016", "T1566.002")
    dataset = AttackDataset(load_attack_data(), domain="enterprise-attack", attack_version="16.1")

    techniques = _by_id(build_layer(dataset, [dataset.find_actor("APT28"), dataset.find_actor("APT29")]))

    assert techniques["T1566.002"]["score"] == 2
    assert techniques["T1566.002"]["comment"] == "Used by: APT28, APT29"
    assert techniques["T1059.001"]["score"] == 1
    assert "score" not in techniques["T1566"]


def test_default_name_with_actors(dataset: AttackDataset) -> None:
    actors = [dataset.find_actor("APT28"), dataset.find_actor("APT29")]

    assert build_layer(dataset, actors)["name"] == "APT28, APT29 (enterprise-attack)"
