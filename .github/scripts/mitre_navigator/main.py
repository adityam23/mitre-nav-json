# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "mitreattack-python>=6.2.1",
#     "pooch>=1.9.0",
#     "pyyaml>=6.0.3",
# ]
# ///
"""Command line entry point: ``mitre-navigator {validate,generate,sync}``."""

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import releases
import upstream
from config import ConfigError, LayerRequest, find_layers, find_requests, load_request, output_filename_for
from errors import RequestError
from layer import Layer, build_layer
from stix import AttackDataset, DatasetRepository, ThreatActor

DEFAULT_INPUT_DIR = Path("mitre_input")
DEFAULT_OUTPUT_DIR = Path("mitre_output")


@dataclass(frozen=True)
class ResolvedRequest:
    request: LayerRequest
    dataset: AttackDataset
    actors: tuple[ThreatActor, ...]


def resolve(request: LayerRequest, repository: DatasetRepository) -> ResolvedRequest:
    """Load a request's dataset and resolve every threat actor it names."""
    dataset = repository.get(request.domain, request.version)
    # dict.fromkeys de-duplicates while keeping order: "APT28" and "Fancy Bear" are the same actor.
    actors = tuple(dict.fromkeys(dataset.find_actor(ref) for ref in request.threat_actors))
    return ResolvedRequest(request=request, dataset=dataset, actors=actors)


def write_layer(layer: Layer, resolved: ResolvedRequest, output_dir: Path) -> Path:
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


def main(
    argv: Sequence[str] | None = None,
    *,
    repository: DatasetRepository | None = None,
) -> int:
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
    latest_domains: set[str] = set()
    for path in paths:
        try:
            if path in collisions:
                raise ConfigError(collisions[path])
            request = load_request(path)
            # Noted before resolving: an actor missing from "latest" may be in a release the library lacks.
            if request.follows_latest:
                latest_domains.add(request.domain)
            resolved = resolve(request, repository)
            # validate builds the layer too.
            layer = build_layer(resolved.dataset, resolved.actors, name=resolved.request.layer_name)
            if writes_layers:
                destination = write_layer(layer, resolved, args.output_dir)
                print(f"{path}: wrote {destination}")
            else:
                print(f"{path}: OK ({_summary(resolved)})")
        except RequestError as exc:
            _report("error", str(exc), path=path)
            failures += 1

    # Failed requests keep their last good layer; only layers without a request file are removed.
    if args.command == "sync":
        for layer in prune_layers(paths, args.output_dir):
            print(f"{layer}: removed (no request file)")

    if latest_domains:
        _warn_if_library_outdated(sorted(latest_domains))
    return 1 if failures else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mitre-navigator", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="check request files without writing output")
    generate = commands.add_parser("generate", help="write a Navigator layer for each request file")
    sync = commands.add_parser("sync", help="generate every request and remove layers whose request is gone")
    sync.set_defaults(files=[])

    for command in (validate, generate):
        command.add_argument("files", nargs="*", type=Path, help="default: every request in --input-dir")
    for command in (validate, generate, sync):
        command.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    for command in (generate, sync):
        command.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
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
        summary += f"; {actor.label}: {len(dataset.techniques_used_by(actor))} techniques"
    return summary


def _warn_if_library_outdated(domains: Sequence[str]) -> None:
    """Warn when MITRE has published releases of ``domains`` that the installed mitreattack-python does not know."""
    try:
        published = upstream.published_releases()
    except upstream.ReleaseIndexError as exc:
        _report("notice", f"could not check for newer ATT&CK releases: {exc}")
        return
    for domain in domains:
        # An index without the domain is treated as unreadable, not as "none newer".
        if not (versions := published.get(domain)):
            _report("notice", f"could not check for newer {domain} releases: {upstream.INDEX_URL} lists none")
            continue
        if unknown := releases.unknown(domain, versions):
            upgrade = f"uv lock --script {os.path.relpath(__file__)} --upgrade-package mitreattack-python"
            _report(
                "warning",
                f"MITRE has published {domain} {', '.join(unknown)}, which the installed mitreattack-python does not "
                f'know, so "latest" still means {releases.LATEST_VERSION}; '
                f"upgrade once a newer mitreattack-python is released: {upgrade}",
            )


def _report(level: Literal["error", "warning", "notice"], message: str, *, path: Path | None = None) -> None:
    """Print to stderr and, on GitHub Actions, annotate the run."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        location = f" file={path}" if path else ""
        print(f"::{level}{location}::{message}")
    prefix = f"{path}: " if path else ""
    print(f"{prefix}{level}: {message}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
