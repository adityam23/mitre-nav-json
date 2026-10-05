from pathlib import Path

import pytest
from mitreattack import release_info

from config import ConfigError, LayerRequest, load_request, parse_request

SOURCE = Path("mitre_input/apt28.yaml")


def test_load_request_full(tmp_path: Path) -> None:
    path = tmp_path / "apt28.yaml"
    path.write_text(
        'domain: enterprise-attack\nversion: "16.1"\nthreat_actors:\n  - APT28\n  - " Fancy Bear "\n  - APT28\n'
        "layer_name: APT28 coverage\n"
    )

    assert load_request(path) == LayerRequest(
        source=path,
        domain="enterprise-attack",
        version="16.1",
        threat_actors=("APT28", "Fancy Bear"),
        layer_name="APT28 coverage",
    )


def test_defaults() -> None:
    request = parse_request({"domain": "ics-attack"}, source=SOURCE)

    assert request.version == release_info.LATEST_VERSION
    assert request.threat_actors == ()
    assert request.layer_name is None
    assert request.output_filename == "apt28.json"


@pytest.mark.parametrize("version", ["latest", " latest "])
def test_latest_resolves_to_newest_release(version: str) -> None:
    request = parse_request({"domain": "enterprise-attack", "version": version}, source=SOURCE)

    assert request.version == release_info.LATEST_VERSION


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (["not", "a", "mapping"], "top level must be a mapping"),
        ({"domain": "enterprise-attack", "actor": "APT28"}, "unknown keys: actor"),
        ({"domain": "pre-attack"}, "'domain' must be one of"),
        ({}, "'domain' must be one of"),
        ({"domain": "enterprise-attack", "version": 16.1}, "quoted string"),
        ({"domain": "enterprise-attack", "version": "v16"}, "not a known enterprise-attack release"),
        ({"domain": "enterprise-attack", "version": "99.9"}, "not a known enterprise-attack release"),
        ({"domain": "enterprise-attack", "threat_actors": "APT28"}, "must be a list"),
        ({"domain": "enterprise-attack", "threat_actors": [""]}, "non-empty strings"),
        ({"domain": "enterprise-attack", "layer_name": ""}, "'layer_name' must be a non-empty string"),
    ],
)
def test_invalid_requests(data: object, message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        parse_request(data, source=SOURCE)


def test_invalid_yaml(tmp_path: Path) -> None:
    path = tmp_path / "broken.yaml"
    path.write_text("domain: [unclosed\n")

    with pytest.raises(ConfigError, match="cannot read YAML"):
        load_request(path)
