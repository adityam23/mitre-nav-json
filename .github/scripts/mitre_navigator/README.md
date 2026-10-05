# mitre_navigator converter

The script behind `mitre-layers.yml`: it turns the requests in `mitre_input/` into ATT&CK Navigator layers in `mitre_output/`. The request format and workflow behaviour are described in the [root README](../../../README.md).

It is a [uv script](https://docs.astral.sh/uv/guides/scripts/), not a package. `main.py` declares its dependencies in inline script metadata and they are locked in `main.py.lock`. The other modules are plain siblings that `main.py` imports directly.

STIX 2.1 data from [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) is downloaded, SHA-256 verified and queried with mitreattack-python, and layers are built with its `navlayers` module. Downloads are cached in the user cache directory (e.g. `~/.cache/mitre-navigator` on Linux) or in `$MITRE_NAVIGATOR_CACHE_DIR`, which CI persists between runs.

## Running locally

Only [uv](https://docs.astral.sh/uv/) is needed. Run the converter from the repository root so `mitre_input/` and `mitre_output/` resolve:

```sh
uv run --locked --script .github/scripts/mitre_navigator/main.py validate                       # every request in mitre_input/
uv run --locked --script .github/scripts/mitre_navigator/main.py validate mitre_input/apt28.yaml
uv run --locked --script .github/scripts/mitre_navigator/main.py generate                       # every request; never removes layers
uv run --locked --script .github/scripts/mitre_navigator/main.py generate mitre_input/apt28.yaml
uv run --locked --script .github/scripts/mitre_navigator/main.py sync                           # generate, then remove orphaned layers; what CI runs
```

Tests are not run in CI, so run them before pushing.

From the repository root:

```sh
uv run --no-project --with pytest --with-requirements <(uv export --script .github/scripts/mitre_navigator/main.py --locked) pytest .github/scripts/mitre_navigator
```

From `.github/scripts/mitre_navigator/`:

```sh
uv run --no-project --with pytest --with-requirements <(uv export --script main.py --locked) pytest
```

The tests use the locked dependencies through `uv export`; `--with-requirements main.py` would ignore the lockfile.

## Updating dependencies

To pick up a new ATT&CK release, upgrade mitreattack-python. This updates `main.py.lock` to the newest version on PyPI; `main.py` does not need editing. Commit the new lockfile in a pull request; CI then regenerates every `version: latest` layer against the new release.

```sh
uv lock --script .github/scripts/mitre_navigator/main.py --upgrade-package mitreattack-python   # from the repository root
uv lock --script main.py --upgrade-package mitreattack-python                                   # from .github/scripts/mitre_navigator/
```

To add, remove or change a dependency, edit the `dependencies` list at the top of `main.py`, then refresh the lockfile:

```sh
uv lock --script .github/scripts/mitre_navigator/main.py   # from the repository root
uv lock --script main.py                                   # from .github/scripts/mitre_navigator/
```
