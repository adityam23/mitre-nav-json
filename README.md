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

`latest` means the newest ATT&CK release known to the installed [mitreattack-python](https://github.com/mitre-attack/mitreattack-python) (`release_info.LATEST_VERSION`), so picking up a new ATT&CK release means bumping that dependency (see the [converter README](.github/scripts/mitre_navigator/README.md)). Domains and pinned versions are validated against the same release list.

The output file is named after the request file, so `mitre_input/apt28.yaml` produces `mitre_output/apt28.json`. Load it in the Navigator via *Open Existing Layer → Upload from local*.

Layers show technique and tactic names without IDs. The layer lists every active (non-revoked, non-deprecated) technique in the dataset. Techniques used by any listed actor, either directly or through a campaign attributed to that actor, get color `#ff0000`, a comment naming the actors and a score equal to the number of listed actors that use the technique, so overlap can be sorted or filtered on in the Navigator. This matches the "Techniques Used" table on attack.mitre.org group pages; techniques that come only from the actor's software are not highlighted.

## Workflows

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `mitre-layers.yml` | Pull request or push to `main` touching `mitre_input/` or the converter, or manual run | Runs the converter's `sync` command and commits the layers to the branch being built. Problems are annotated on the request file. |

On a pull request the layers are committed to the PR branch, so you can review them and the merge already contains them. On `main` the same job acts as a safety net: it normally finds nothing to change and only commits when `main` drifted, for example after two PRs were merged back to back or after a direct push. Pull requests from forks are checked but not committed to, because the workflow token cannot push to forks.

`sync` makes `mitre_output/` match `mitre_input/` on every run instead of tracking which files changed, so a request that failed earlier is picked up again as soon as it is fixed:

- Every request is regenerated; unchanged requests produce identical files, so they never create commits.
- A request that fails keeps its last good layer. The other requests are still generated and committed, and the run is marked failed afterwards.
- Layers whose request file was deleted or renamed are removed. `mitre_output/` is owned by the workflow, so do not put hand-made layers there.

The workflow pushes with `GITHUB_TOKEN`. Commits made with that token do not trigger workflows, so the generated-layers commit on a PR shows no checks of its own; if you add a branch rule that requires status checks, the merge will be blocked. If `main` is protected, also allow GitHub Actions to bypass the rule, or the safety-net push will be rejected.

The converter lives in `.github/scripts/mitre_navigator/`; see its [README](.github/scripts/mitre_navigator/README.md) for running it locally.
