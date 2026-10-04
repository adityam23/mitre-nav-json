# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "mitreattack-python>=6.2.1",
#     "pooch>=1.9.0",
#     "pyyaml>=6.0.3",
# ]
# ///
"""Command line entry point: ``mitre-navigator {validate,generate,sync}``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from config import ConfigError, LayerRequest, find_layers, find_requests, load_request, output_filename_for
from layer import LayerBuildError, build_layer
from stix import ActorLookupError, AttackDataset, DatasetError, DatasetRepository, ThreatActor

DEFAULT_INPUT_DIR = Path("mitre_input")
DEFAULT_OUTPUT_DIR = Path("mitre_output")


@dataclass(frozen=True)
class ResolvedRequest:
    request: LayerRequest
    dataset: AttackDataset
    actors: tuple[ThreatActor, ...]


def resolve(path: Path, repository: DatasetRepository) -> ResolvedRequest:
    """Parse a request file, load its dataset and resolve every threat actor it names."""
    request = load_request(path)
    dataset = repository.get(request.domain, request.version)
    # dict.fromkeys de-duplicates while keeping order: "APT28" and "Fancy Bear" are the same actor.
    actors = tuple(dict.fromkeys(dataset.find_actor(ref) for ref in request.threat_actors))
    return ResolvedRequest(request=request, dataset=dataset, actors=actors)


def write_layer(resolved: ResolvedRequest, output_dir: Path) -> Path:
    layer = build_layer(resolved.dataset, resolved.actors, name=resolved.request.layer_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / resolved.request.output_filename
    destination.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    return destination


def prune_layers(requests: Sequence[Path], output_dir: Path) -> list[Path]:
    """Delete layers in ``output_dir`` that no request in ``requests`` generates."""
    expected = {output_filename_for(path) for path in requests}
    orphans = [layer for layer in find_layers(output_dir) if layer.name not in expected]
    for layer in orphans:
        layer.unlink()
    return orphans


def main(argv: Sequence[str] | None = None, *, repository: DatasetRepository | None = None) -> int:
    args = _parser().parse_args(argv)
    repository = repository or DatasetRepository()
    writes_layers = args.command in ("generate", "sync")

    try:
        paths = args.files or find_requests(args.input_dir)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Each request is handled independently, so one broken file never blocks the others.
    collisions = _output_collisions(paths)
    failures = 0
    for path in paths:
        try:
            if path in collisions:
                raise ConfigError(collisions[path])
            resolved = resolve(path, repository)
            if writes_layers:
                destination = write_layer(resolved, args.output_dir)
                print(f"{path}: wrote {destination}")
            else:
                print(f"{path}: OK ({_summary(resolved)})")
        except (ConfigError, DatasetError, ActorLookupError, LayerBuildError) as exc:
            _report_error(path, str(exc))
            failures += 1

    # Failed requests keep their last good layer; only layers without a request file are removed.
    if args.command == "sync":
        for layer in prune_layers(paths, args.output_dir):
            print(f"{layer}: removed (no request file)")

    return 1 if failures else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mitre-navigator", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="check request files without writing output")
    validate.add_argument("files", nargs="*", type=Path, help="default: every request in --input-dir")
    validate.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)

    generate = commands.add_parser("generate", help="write a Navigator layer for each request file")
    generate.add_argument("files", nargs="+", type=Path)
    generate.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)

    sync = commands.add_parser(
        "sync", help="regenerate every request in --input-dir and remove layers whose request is gone"
    )
    sync.set_defaults(files=[])
    sync.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    sync.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser


def _output_collisions(paths: Sequence[Path]) -> Mapping[Path, str]:
    """Error message for every request whose layer name is shared with another request."""
    by_name: dict[str, list[Path]] = {}
    for path in paths:
        by_name.setdefault(output_filename_for(path), []).append(path)
    return {
        path: f"output {name} is also generated from {', '.join(str(p) for p in group if p != path)}"
        for name, group in by_name.items()
        if len(group) > 1
        for path in group
    }


def _summary(resolved: ResolvedRequest) -> str:
    dataset = resolved.dataset
    summary = f"{dataset.domain} v{dataset.attack_version}, {len(dataset.techniques)} techniques"
    for actor in resolved.actors:
        summary += f"; {actor.name} ({actor.attack_id}): {len(dataset.techniques_used_by(actor))} techniques"
    return summary


def _report_error(path: Path, message: str) -> None:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::error file={path}::{message}")
    print(f"{path}: error: {message}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
