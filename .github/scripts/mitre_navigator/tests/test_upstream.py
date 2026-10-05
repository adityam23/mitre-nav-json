import http.client

import pytest

import upstream
from upstream import ReleaseIndexError, parse_index


def _collection(domain: str, *versions: str) -> dict[str, object]:
    base = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
    return {"versions": [{"version": v, "url": f"{base}/{domain}/{domain}-{v}.json"} for v in versions]}


def test_parse_index_lists_releases_per_domain() -> None:
    index = {"collections": [_collection("enterprise-attack", "19.2", "19.1"), _collection("ics-attack", "19.2")]}

    assert parse_index(index) == {"enterprise-attack": ("19.2", "19.1"), "ics-attack": ("19.2",)}


@pytest.mark.parametrize(
    "index",
    [
        {},
        [],
        {"collections": "x"},
        {"collections": [{"versions": []}]},
        {"collections": [{"versions": [{"version": "19.2", "url": 123}]}]},
        {"collections": [{"versions": [{"version": ["19.2"], "url": "https://example.com/ics-attack/x.json"}]}]},
    ],
)
def test_parse_index_rejects_unknown_layouts(index: object) -> None:
    with pytest.raises(ReleaseIndexError, match="unexpected layout"):
        parse_index(index)


def test_dropped_connection_is_a_release_index_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def dropped(*args: object, **kwargs: object) -> None:
        raise http.client.IncompleteRead(b"{")

    monkeypatch.setattr(upstream.urllib.request, "urlopen", dropped)

    with pytest.raises(ReleaseIndexError, match="cannot read"):
        upstream.published_releases()


def test_releases_for_a_domain_missing_from_the_index_is_an_error() -> None:
    with pytest.raises(ReleaseIndexError, match="lists no enterprise-attack releases"):
        upstream.releases_for({"ics-attack": ("19.2",)}, "enterprise-attack")
