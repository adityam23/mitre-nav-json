# mitre_navigator converter

The script behind `mitre-layers.yml`: it turns the requests in `mitre_input/` into ATT&CK Navigator layers in `mitre_output/`. The request format and workflow behaviour are described in the [root README](../../../README.md).

It is a [uv script](https://docs.astral.sh/uv/guides/scripts/), not a package. `main.py` declares its dependencies in inline script metadata and they are locked in `main.py.lock`. The other modules are plain siblings that `main.py` imports directly.

STIX 2.1 data from [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) is downloaded, SHA-256 verified and queried with mitreattack-python, and layers are built with its `navlayers` module. Downloads are cached in the user cache directory (e.g. `~/.cache/mitre-navigator` on Linux) or in `$MITRE_NAVIGATOR_CACHE_DIR`, which CI persists between runs.

## Running locally

Only [uv](https://docs.astral.sh/uv/) is needed. Run the converter from the repository root so `mitre_input/` and `mitre_output/` resolve:

```sh
uv run --locked --script .github/scripts/mitre_navigator/main.py validate                       # every request in mitre_input/
uv run --locked --script .github/scripts/mitre_navigator/main.py validate mitre_input/apt28.yaml
uv run --locked --script .github/scripts/mitre_navigator/main.py generate mitre_input/apt28.yaml
uv run --locked --script .github/scripts/mitre_navigator/main.py sync                           # what CI runs
```

Tests are not run in CI, and changes to them or to this README do not trigger the layers workflow, so run them before pushing. From this directory:

```sh
uv run --no-project --with pytest --with-requirements <(uv export --script main.py --locked) pytest
```

The tests use the locked dependencies through `uv export`; `--with-requirements main.py` would ignore the lockfile.

## Updating dependencies

Edit the `dependencies` list at the top of `main.py` if needed, then refresh the lockfile:

```sh
uv lock --script main.py                                        # after editing the dependency list
uv lock --script main.py --upgrade-package mitreattack-python   # pick up a new ATT&CK release
```
