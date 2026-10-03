# MITRE ATT&CK Navigator layer generator

Drop a YAML request into `mitre_input/` via a pull request and GitHub Actions turns it into an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer in `mitre_output/`. If the request names threat actors, every technique they use is colored red.

## Request format

```yaml
# mitre_input/apt28.yaml
domain: enterprise-attack   # enterprise-attack | mobile-attack | ics-attack
version: latest             # optional, default "latest"; or a quoted ATT&CK release such as "16.1"
threat_actors:              # optional
  - APT28                   # name, alias (e.g. "Fancy Bear") or ATT&CK group ID (e.g. G0007), case-insensitive
layer_name: APT28 coverage  # optional
```

`latest` means the newest ATT&CK release known to the installed [mitreattack-python](https://github.com/mitre-attack/mitreattack-python) (`release_info.LATEST_VERSION`), so picking up a new ATT&CK release means bumping that dependency in `uv.lock`. Domains and pinned versions are validated against the same release list.

The output file is named after the request file, so `mitre_input/apt28.yaml` produces `mitre_output/apt28.json`. Load it in the Navigator via *Open Existing Layer → Upload from local*.

The layer lists every active (non-revoked, non-deprecated) technique in the dataset. Techniques used by any listed actor, either directly or through a campaign attributed to that actor, get color `#ff0000`, a score of 1 and a comment naming the actors. This matches the "Techniques Used" table on attack.mitre.org group pages; techniques that come only from the actor's software are not highlighted.

## Workflows

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `mitre-validate.yml` | Pull request touching `mitre_input/` | Parses the added or changed requests, downloads the dataset and resolves every threat actor. Problems are annotated on the PR file. Nothing is committed. |
| `mitre-generate.yml` | Push to `main` touching `mitre_input/`, or manual run | Generates layers for the added or changed requests (all requests on a manual run) and commits them to `mitre_output/`. |
| `tests.yml` | Changes to the code | Runs the test suite. |

STIX 2.1 data from [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) is downloaded, SHA-256 verified and queried with mitreattack-python, and layers are built with its `navlayers` module. Downloads are cached in the user cache directory (e.g. `~/.cache/mitre-navigator` on Linux).

The generate workflow pushes to `main` with `GITHUB_TOKEN`. If `main` is protected, allow GitHub Actions to bypass the rule, or the push will be rejected.

## Local development

```sh
uv sync
uv run pytest
uv run mitre-navigator validate mitre_input/apt28.yaml
uv run mitre-navigator generate mitre_input/apt28.yaml --output-dir mitre_output
```
