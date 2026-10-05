"""Parsing and validation of the YAML request files placed in ``mitre_input/``."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

import releases
from errors import RequestError

_ALLOWED_KEYS = frozenset({"domain", "version", "threat_actors", "layer_name"})
_REQUEST_SUFFIXES = (".yaml", ".yml")
_LAYER_SUFFIX = ".json"


class ConfigError(RequestError):
    """Raised when a request file is malformed."""


@dataclass(frozen=True)
class LayerRequest:
    """A validated request to generate one Navigator layer."""

    source: Path
    domain: str
    version: str
    follows_latest: bool
    threat_actors: tuple[str, ...]
    layer_name: str | None

    @property
    def output_filename(self) -> str:
        return output_filename_for(self.source)


def output_filename_for(source: Path) -> str:
    """Name of the Navigator layer generated from ``source`` (e.g. apt28.yaml -> apt28.json)."""
    return f"{source.stem}{_LAYER_SUFFIX}"


def find_requests(input_dir: Path) -> list[Path]:
    """Every request file in ``input_dir``, sorted by name."""
    # A missing directory is an error rather than "no requests", so sync never prunes every layer by mistake.
    if not input_dir.is_dir():
        raise ConfigError(f"request directory {input_dir} does not exist")
    return sorted(path for path in input_dir.iterdir() if path.is_file() and path.suffix in _REQUEST_SUFFIXES)


def find_layers(output_dir: Path) -> list[Path]:
    """Every generated layer file in ``output_dir``, sorted by name."""
    if not output_dir.is_dir():
        return []
    return sorted(path for path in output_dir.iterdir() if path.is_file() and path.suffix == _LAYER_SUFFIX)


def load_request(path: Path) -> LayerRequest:
    """Read and validate a request file."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"cannot read YAML: {exc}") from exc
    return parse_request(data, source=path)


def parse_request(data: Any, *, source: Path) -> LayerRequest:
    """Validate an already-parsed YAML document."""
    if not isinstance(data, dict):
        raise ConfigError("top level must be a mapping")

    unknown = sorted(set(data) - _ALLOWED_KEYS)
    if unknown:
        raise ConfigError(f"unknown keys: {', '.join(unknown)} (allowed: {', '.join(sorted(_ALLOWED_KEYS))})")

    domain = _parse_domain(data.get("domain"))
    version = _parse_version(data.get("version", releases.LATEST))
    return LayerRequest(
        source=source,
        domain=domain,
        version=_resolve_release(domain, version),
        follows_latest=version == releases.LATEST,
        threat_actors=_parse_threat_actors(data.get("threat_actors")),
        layer_name=_parse_layer_name(data.get("layer_name")),
    )


def _parse_domain(value: Any) -> str:
    if value not in releases.DOMAINS:
        raise ConfigError(f"'domain' must be one of {', '.join(releases.DOMAINS)}; got {value!r}")
    return value


def _parse_version(value: Any) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"'version' must be a quoted string such as \"16.1\" or \"latest\"; got {value!r}")
    return value.strip()


def _resolve_release(domain: str, version: str) -> str:
    """A concrete ATT&CK release; ``latest`` becomes the newest release the installed library knows."""
    release = releases.resolve(domain, version)
    if release is None:
        raise ConfigError(
            f"'version' {version!r} is not a known {domain} release; "
            f"use \"latest\" ({releases.LATEST_VERSION}) or an ATT&CK release such as \"16.1\""
        )
    return release


def _parse_threat_actors(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError("'threat_actors' must be a list of names, aliases or ATT&CK group IDs")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ConfigError(f"'threat_actors' entries must be non-empty strings; got {item!r}")
    # dict.fromkeys drops repeated names while keeping the order they were listed in.
    return tuple(dict.fromkeys(item.strip() for item in value))


def _parse_layer_name(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("'layer_name' must be a non-empty string")
    return value.strip()
