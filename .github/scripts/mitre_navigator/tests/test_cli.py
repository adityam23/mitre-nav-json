import json
from pathlib import Path

import pytest

from main import main
from stix import DatasetRepository


@pytest.fixture
def inputs(tmp_path: Path) -> Path:
    directory = tmp_path / "mitre_input"
    directory.mkdir()
    return directory


def test_generate_writes_layer(inputs: Path, tmp_path: Path, repository: DatasetRepository) -> None:
    request = inputs / "apt28.yaml"
    request.write_text("domain: enterprise-attack\nthreat_actors: [Fancy Bear]\n")
    output_dir = tmp_path / "mitre_output"

    assert main(["generate", str(request), "--output-dir", str(output_dir)], repository=repository) == 0

    layer = json.loads((output_dir / "apt28.json").read_text())
    red = sorted(t["techniqueID"] for t in layer["techniques"] if t.get("color") == "#ff0000")
    assert red == ["T1059.001", "T1566.002"]


def test_actor_listed_by_several_names_counts_once(
    inputs: Path, tmp_path: Path, repository: DatasetRepository
) -> None:
    request = inputs / "apt28.yaml"
    request.write_text("domain: enterprise-attack\nthreat_actors: [APT28, Fancy Bear, G0007]\n")
    output_dir = tmp_path / "mitre_output"

    assert main(["generate", str(request), "--output-dir", str(output_dir)], repository=repository) == 0

    layer = json.loads((output_dir / "apt28.json").read_text())
    scored = {t["techniqueID"]: (t["score"], t["comment"]) for t in layer["techniques"] if "score" in t}
    assert scored == {"T1059.001": (1, "Used by: APT28"), "T1566.002": (1, "Used by: APT28")}
    assert layer["metadata"] == [{"name": "threat_actor", "value": "APT28 (G0007)"}]


def test_validate_does_not_write(
    inputs: Path, repository: DatasetRepository, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(inputs.parent)
    request = inputs / "apt28.yaml"
    request.write_text("domain: enterprise-attack\nthreat_actors: [G0007]\n")

    assert main(["validate", str(request)], repository=repository) == 0

    assert "APT28 (G0007): 2 techniques" in capsys.readouterr().out
    assert not (inputs.parent / "mitre_output").exists()


def test_errors_are_reported_per_file_and_fail_the_run(
    inputs: Path,
    tmp_path: Path,
    repository: DatasetRepository,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    good = inputs / "good.yaml"
    good.write_text("domain: enterprise-attack\n")
    bad = inputs / "bad.yaml"
    bad.write_text("domain: enterprise-attack\nthreat_actors: [Nobody]\n")
    output_dir = tmp_path / "out"

    assert main(["generate", str(bad), str(good), "--output-dir", str(output_dir)], repository=repository) == 1

    captured = capsys.readouterr()
    assert f"::error file={bad}::threat actor 'Nobody' not found" in captured.out
    assert (output_dir / "good.json").exists()
    assert not (output_dir / "bad.json").exists()


def test_colliding_output_names_fail_only_those_requests(
    inputs: Path, tmp_path: Path, repository: DatasetRepository, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("apt28.yaml", "apt28.yml", "other.yaml"):
        (inputs / name).write_text("domain: enterprise-attack\n")
    output_dir = tmp_path / "out"
    files = [str(inputs / name) for name in ("apt28.yaml", "apt28.yml", "other.yaml")]

    assert main(["generate", *files, "--output-dir", str(output_dir)], repository=repository) == 1

    assert capsys.readouterr().err.count("is also generated from") == 2
    assert [p.name for p in output_dir.iterdir()] == ["other.json"]


def _sync(inputs: Path, output_dir: Path, repository: DatasetRepository) -> int:
    return main(["sync", "--input-dir", str(inputs), "--output-dir", str(output_dir)], repository=repository)


def test_sync_regenerates_every_request_despite_failures(
    inputs: Path, tmp_path: Path, repository: DatasetRepository
) -> None:
    (inputs / "a.yaml").write_text("domain: enterprise-attack\n")
    (inputs / "broken.yaml").write_text("domain: enterprise-attack\nthreat_actors: [Nobody]\n")
    (inputs / "c.yml").write_text("domain: enterprise-attack\nthreat_actors: [APT28]\n")
    (inputs / "notes.txt").write_text("not a request\n")
    output_dir = tmp_path / "out"

    assert _sync(inputs, output_dir, repository) == 1

    assert sorted(p.name for p in output_dir.iterdir()) == ["a.json", "c.json"]


def test_sync_keeps_last_good_layer_of_broken_request(
    inputs: Path, tmp_path: Path, repository: DatasetRepository
) -> None:
    request = inputs / "apt28.yaml"
    request.write_text("domain: enterprise-attack\nthreat_actors: [APT28]\n")
    output_dir = tmp_path / "out"
    assert _sync(inputs, output_dir, repository) == 0
    good = (output_dir / "apt28.json").read_text()

    request.write_text("domain: enterprise-attack\nthreat_actors: [Nobody]\n")

    assert _sync(inputs, output_dir, repository) == 1
    assert (output_dir / "apt28.json").read_text() == good


def test_sync_removes_layers_without_request_and_is_deterministic(
    inputs: Path, tmp_path: Path, repository: DatasetRepository, capsys: pytest.CaptureFixture[str]
) -> None:
    (inputs / "kept.yaml").write_text("domain: enterprise-attack\n")
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "deleted-request.json").write_text("{}")
    (output_dir / ".gitkeep").write_text("")

    assert _sync(inputs, output_dir, repository) == 0
    first = (output_dir / "kept.json").read_text()
    assert _sync(inputs, output_dir, repository) == 0

    assert sorted(p.name for p in output_dir.iterdir()) == [".gitkeep", "kept.json"]
    assert (output_dir / "kept.json").read_text() == first
    assert "deleted-request.json: removed (no request file)" in capsys.readouterr().out


def test_sync_refuses_missing_input_dir(
    tmp_path: Path, repository: DatasetRepository, capsys: pytest.CaptureFixture[str]
) -> None:
    output_dir = tmp_path / "out"
    output_dir.mkdir()
    (output_dir / "layer.json").write_text("{}")

    assert _sync(tmp_path / "missing", output_dir, repository) == 1

    assert "does not exist" in capsys.readouterr().err
    assert (output_dir / "layer.json").exists()


def test_validate_without_files_checks_every_request(
    inputs: Path, repository: DatasetRepository, capsys: pytest.CaptureFixture[str]
) -> None:
    (inputs / "good.yaml").write_text("domain: enterprise-attack\n")
    (inputs / "broken.yaml").write_text("domain: enterprise-attack\nthreat_actors: [Nobody]\n")

    assert main(["validate", "--input-dir", str(inputs)], repository=repository) == 1

    captured = capsys.readouterr()
    assert "good.yaml: OK" in captured.out
    assert "broken.yaml: error: threat actor 'Nobody' not found" in captured.err
