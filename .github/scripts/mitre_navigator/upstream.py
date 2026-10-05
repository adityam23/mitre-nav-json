"""The ATT&CK releases MITRE has published, read from its collection index."""

import http.client
import json
import urllib.request
from collections.abc import Mapping
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

INDEX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
_TIMEOUT_SECONDS = 10


class ReleaseIndexError(Exception):
    """Raised when MITRE's collection index cannot be fetched or understood."""


def published_releases() -> dict[str, tuple[str, ...]]:
    """Every published release of each domain (e.g. ``{"enterprise-attack": ("19.2", ...)}``)."""
    try:
        with urllib.request.urlopen(INDEX_URL, timeout=_TIMEOUT_SECONDS) as response:
            index = json.load(response)
    # HTTPException covers failures outside OSError, such as a connection dropped mid-body (IncompleteRead).
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise ReleaseIndexError(f"cannot read {INDEX_URL}: {exc}") from exc
    return parse_index(index)


def parse_index(index: Any) -> dict[str, tuple[str, ...]]:
    """Releases per domain from an index.json document."""
    try:
        return {
            _domain(collection): tuple(_text(version["version"]) for version in collection["versions"])
            for collection in index["collections"]
        }
    except (KeyError, TypeError, IndexError) as exc:
        raise ReleaseIndexError(f"unexpected layout of {INDEX_URL}: {exc!r}") from exc


def _domain(collection: Mapping[str, Any]) -> str:
    # Bundles live under a directory named after their domain: .../enterprise-attack/enterprise-attack-19.2.json
    return PurePosixPath(urlparse(_text(collection["versions"][0]["url"])).path).parent.name


def _text(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError(f"expected a string, got {value!r}")
    return value
