import json
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

import pytest

import releases
import upstream
from main import main
from stix import DatasetRepository


class Run(Protocol):
    def __call__(self, argv: Sequence[str], *, published_releases: upstream.ReleaseFetcher | None = None) -> int: ...


@pytest.fixture
def inputs(tmp_path: Path) -> Path:
    directory = tmp_path / "mitre_input"
    directory.mkdir()
    return directory


@pytest.fixture
def published() -> dict[str, tuple[str, ...]]:
    """Releases in the stand-in for MITRE's index; tests may add some."""
    return {}


@pytest.fixture
def run(repository: DatasetRepository, published: dict[str, tuple[str, ...]]) -> Run:
    """``main`` against the test dataset and release index (or a given fetcher), so no test reaches the network."""

    def run(argv: Sequence[str], *, published_releases: upstream.ReleaseFetcher | None = None) -> int:
        return main(argv, repository=repository, published_releases=published_releases or (lambda: published))

    return run


def test_generate_writes_layer(inputs: Path, tmp_path: Path, run: Run) -> None:
    request = inputs / "apt28.yaml"
    request.write_text("domain: enterprise-attack\nthreat_actors: [Fancy Bear]\n")
    output_dir = tmp_path / "mitre_output"

    assert run(["generate", str(request), "--output-dir", str(output_dir)]) == 0

    layer = json.loads((output_dir / "apt28.json").read_text())
    red = sorted(t["techniqueID"] for t in layer["techniques"] if t.get("color") == "#ff0000")
    assert red == ["T1059.001", "T1566.002"]


def test_generate_without_files_generates_every_request(
    inputs: Path, tmp_path: Path, run: Run
) -> None:
    (inputs / "a.yaml").write_text("domain: enterprise-attack\n")
    (inputs / "b.yml").write_text("domain: enterprise-attack\nthreat_actors: [APT28]\n")
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "orphan.json").write_text("{}")

    assert run(["generate", "--input-dir", str(inputs), "--output-dir", str(output_dir)]) == 0

    # Unlike sync, generate never removes layers.
    assert sorted(p.name for p in output_dir.iterdir()) == ["a.json", "b.json", "orphan.json"]


def test_actor_listed_by_several_names_counts_once(
    inputs: Path, tmp_path: Path, run: Run
) -> None:
    request = inputs / "apt28.yaml"
    request.write_text("domain: enterprise-attack\nthreat_actors: [APT28, Fancy Bear, G0007]\n")
    output_dir = tmp_path / "mitre_output"

    assert run(["generate", str(request), "--output-dir", str(output_dir)]) == 0

    layer = json.loads((output_dir / "apt28.json").read_text())
    scored = {t["techniqueID"]: (t["score"], t["comment"]) for t in layer["techniques"] if "score" in t}
    assert scored == {"T1059.001": (1, "Used by: APT28"), "T1566.002": (1, "Used by: APT28")}
    assert layer["metadata"] == [{"name": "threat_actor", "value": "APT28 (G0007)"}]


def test_validate_does_not_write(
    inputs: Path, run: Run, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(inputs.parent)
    request = inputs / "apt28.yaml"
    request.write_text("domain: enterprise-attack\nthreat_actors: [G0007]\n")

    assert run(["validate", str(request)]) == 0

    assert "APT28 (G0007): 2 techniques" in capsys.readouterr().out
    assert not (inputs.parent / "mitre_output").exists()


def test_errors_are_reported_per_file_and_fail_the_run(
    inputs: Path,
    tmp_path: Path,
    run: Run,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    good = inputs / "good.yaml"
    good.write_text("domain: enterprise-attack\n")
    bad = inputs / "bad.yaml"
    bad.write_text("domain: enterprise-attack\nthreat_actors: [Nobody]\n")
    output_dir = tmp_path / "out"

    assert run(["generate", str(bad), str(good), "--output-dir", str(output_dir)]) == 1

    captured = capsys.readouterr()
    assert f"::error file={bad}::threat actor 'Nobody' not found" in captured.out
    assert (output_dir / "good.json").exists()
    assert not (output_dir / "bad.json").exists()


def test_colliding_output_names_fail_only_those_requests(
    inputs: Path, tmp_path: Path, run: Run, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("apt28.yaml", "apt28.yml", "other.yaml"):
        (inputs / name).write_text("domain: enterprise-attack\n")
    output_dir = tmp_path / "out"
    files = [str(inputs / name) for name in ("apt28.yaml", "apt28.yml", "other.yaml")]

    assert run(["generate", *files, "--output-dir", str(output_dir)]) == 1

    assert capsys.readouterr().err.count("is also generated from") == 2
    assert [p.name for p in output_dir.iterdir()] == ["other.json"]


def _sync(run: Run, inputs: Path, output_dir: Path) -> int:
    return run(["sync", "--input-dir", str(inputs), "--output-dir", str(output_dir)])


def test_sync_regenerates_every_request_despite_failures(
    inputs: Path, tmp_path: Path, run: Run
) -> None:
    (inputs / "a.yaml").write_text("domain: enterprise-attack\n")
    (inputs / "broken.yaml").write_text("domain: enterprise-attack\nthreat_actors: [Nobody]\n")
    (inputs / "c.yml").write_text("domain: enterprise-attack\nthreat_actors: [APT28]\n")
    (inputs / "notes.txt").write_text("not a request\n")
    output_dir = tmp_path / "out"

    assert _sync(run, inputs, output_dir) == 1

    assert sorted(p.name for p in output_dir.iterdir()) == ["a.json", "c.json"]


def test_sync_keeps_last_good_layer_of_broken_request(
    inputs: Path, tmp_path: Path, run: Run
) -> None:
    request = inputs / "apt28.yaml"
    request.write_text("domain: enterprise-attack\nthreat_actors: [APT28]\n")
    output_dir = tmp_path / "out"
    assert _sync(run, inputs, output_dir) == 0
    good = (output_dir / "apt28.json").read_text()

    request.write_text("domain: enterprise-attack\nthreat_actors: [Nobody]\n")

    assert _sync(run, inputs, output_dir) == 1
    assert (output_dir / "apt28.json").read_text() == good


def test_sync_removes_layers_without_request_and_is_deterministic(
    inputs: Path, tmp_path: Path, run: Run, capsys: pytest.CaptureFixture[str]
) -> None:
    (inputs / "kept.yaml").write_text("domain: enterprise-attack\n")
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "deleted-request.json").write_text("{}")
    (output_dir / ".gitkeep").write_text("")

    assert _sync(run, inputs, output_dir) == 0
    first = (output_dir / "kept.json").read_text()
    assert _sync(run, inputs, output_dir) == 0

    assert sorted(p.name for p in output_dir.iterdir()) == [".gitkeep", "kept.json"]
    assert (output_dir / "kept.json").read_text() == first
    assert "deleted-request.json: removed (no request file)" in capsys.readouterr().out


def test_sync_refuses_missing_input_dir(
    tmp_path: Path, run: Run, capsys: pytest.CaptureFixture[str]
) -> None:
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "layer.json").write_text("{}")

    assert _sync(run, tmp_path / "missing", output_dir) == 1

    assert "does not exist" in capsys.readouterr().err
    assert (output_dir / "layer.json").exists()


def test_validate_without_files_checks_every_request(
    inputs: Path, run: Run, capsys: pytest.CaptureFixture[str]
) -> None:
    (inputs / "good.yaml").write_text("domain: enterprise-attack\n")
    (inputs / "broken.yaml").write_text("domain: enterprise-attack\nthreat_actors: [Nobody]\n")

    assert run(["validate", "--input-dir", str(inputs)]) == 1

    captured = capsys.readouterr()
    assert "good.yaml: OK" in captured.out
    assert "broken.yaml: error: threat actor 'Nobody' not found" in captured.err


def test_warns_when_library_lacks_a_published_release(
    inputs: Path,
    run: Run,
    published: dict[str, tuple[str, ...]],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    published["enterprise-attack"] = ("99.0", releases.LATEST_VERSION)
    (inputs / "latest.yaml").write_text("domain: enterprise-attack\n")

    # A stale library only warns: "latest" keeps meaning the newest release it knows.
    assert run(["validate", "--input-dir", str(inputs)]) == 0

    captured = capsys.readouterr()
    assert "::warning::MITRE has published enterprise-attack 99.0" in captured.out
    assert f'"latest" still means {releases.LATEST_VERSION}' in captured.err
    assert "--upgrade-package mitreattack-python" in captured.err


def test_pinned_versions_skip_the_release_check(inputs: Path, run: Run) -> None:
    def fail() -> dict[str, tuple[str, ...]]:
        raise AssertionError("the release index should not be fetched")

    (inputs / "pinned.yaml").write_text('domain: enterprise-attack\nversion: "16.1"\n')

    assert run(["validate", "--input-dir", str(inputs)], published_releases=fail) == 0


def test_unreachable_release_index_is_only_a_notice(inputs: Path, run: Run, capsys: pytest.CaptureFixture[str]) -> None:
    def unreachable() -> dict[str, tuple[str, ...]]:
        raise upstream.ReleaseIndexError("cannot read index.json: offline")

    (inputs / "latest.yaml").write_text("domain: enterprise-attack\n")

    assert run(["validate", "--input-dir", str(inputs)], published_releases=unreachable) == 0

    notice = "notice: could not check for newer ATT&CK releases: cannot read index.json: offline"
    assert notice in capsys.readouterr().err


def test_failed_latest_request_still_checks_for_newer_releases(
    inputs: Path, run: Run, published: dict[str, tuple[str, ...]], capsys: pytest.CaptureFixture[str]
) -> None:
    # An actor added in a release the library lacks is "not found" in the library's latest.
    published["enterprise-attack"] = ("99.0", releases.LATEST_VERSION)
    (inputs / "new-actor.yaml").write_text("domain: enterprise-attack\nthreat_actors: [Nobody]\n")

    assert run(["validate", "--input-dir", str(inputs)]) == 1

    captured = capsys.readouterr().err
    assert "threat actor 'Nobody' not found" in captured
    assert "MITRE has published enterprise-attack 99.0" in captured


def test_domain_missing_from_release_index_is_a_notice(
    inputs: Path, run: Run, published: dict[str, tuple[str, ...]], capsys: pytest.CaptureFixture[str]
) -> None:
    published["ics-attack"] = (releases.LATEST_VERSION,)
    (inputs / "latest.yaml").write_text("domain: enterprise-attack\n")

    assert run(["validate", "--input-dir", str(inputs)]) == 0

    notice = f"notice: could not check for newer enterprise-attack releases: {upstream.INDEX_URL} lists none"
    assert notice in capsys.readouterr().err
