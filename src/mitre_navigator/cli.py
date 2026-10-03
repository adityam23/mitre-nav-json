"""Command line entry point: ``mitre-navigator {validate,generate} FILE...``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .config import ConfigError, LayerRequest, load_request, output_filename_for
from .layer import LayerBuildError, build_layer
from .stix import ActorLookupError, AttackDataset, DatasetError, DatasetRepository, ThreatActor

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
    actors = tuple(dataset.find_actor(ref) for ref in request.threat_actors)
    return ResolvedRequest(request=request, dataset=dataset, actors=actors)


def write_layer(resolved: ResolvedRequest, output_dir: Path) -> Path:
    layer = build_layer(resolved.dataset, resolved.actors, name=resolved.request.layer_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / resolved.request.output_filename
    destination.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    return destination


def main(argv: Sequence[str] | None = None, *, repository: DatasetRepository | None = None) -> int:
    args = _parser().parse_args(argv)
    repository = repository or DatasetRepository()

    if args.command == "generate" and _has_output_collisions(args.files):
        return 1

    failures = 0
    for path in args.files:
        try:
            resolved = resolve(path, repository)
            if args.command == "generate":
                destination = write_layer(resolved, args.output_dir)
                print(f"{path}: wrote {destination}")
            else:
                print(f"{path}: OK ({_summary(resolved)})")
        except (ConfigError, DatasetError, ActorLookupError, LayerBuildError) as exc:
            _report_error(path, str(exc))
            failures += 1

    return 1 if failures else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mitre-navigator", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="check request files without writing output")
    validate.add_argument("files", nargs="+", type=Path)

    generate = commands.add_parser("generate", help="write a Navigator layer for each request file")
    generate.add_argument("files", nargs="+", type=Path)
    generate.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    return parser


def _has_output_collisions(paths: Sequence[Path]) -> bool:
    seen: dict[str, Path] = {}
    collided = False
    for path in paths:
        name = output_filename_for(path)
        if name in seen:
            _report_error(path, f"output {name} would overwrite the layer generated from {seen[name]}")
            collided = True
        seen.setdefault(name, path)
    return collided


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
