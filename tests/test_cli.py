import json
from pathlib import Path

import pytest

from mitre_navigator.cli import main
from mitre_navigator.stix import DatasetRepository


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


def test_generate_rejects_colliding_output_names(
    inputs: Path, tmp_path: Path, repository: DatasetRepository, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("apt28.yaml", "apt28.yml"):
        (inputs / name).write_text("domain: enterprise-attack\n")

    output_dir = tmp_path / "out"
    args = ["generate", str(inputs / "apt28.yaml"), str(inputs / "apt28.yml"), "--output-dir", str(output_dir)]

    assert main(args, repository=repository) == 1
    assert "would overwrite" in capsys.readouterr().err
    assert not output_dir.exists()
