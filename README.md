# MITRE ATT&CK Navigator layer generator

Write a YAML request in `mitre_input/` and CI generates the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer in `mitre_output/`.

## How to use

1. Add a request, e.g. `mitre_input/apt28.yaml`.
2. Open a pull request. CI commits `mitre_output/apt28.json` to your branch.
3. Wait for that commit and approve it, then merge.
4. Load the layer in the Navigator via *Open Existing Layer → Upload from local*.

Deleting a request deletes its layer. Don't edit `mitre_output/` by hand.

## Request format

See [`mitre_input/`](mitre_input/) for example requests.

```yaml
domain: enterprise-attack   # enterprise-attack | mobile-attack | ics-attack
version: latest             # optional, or a quoted release such as "16.1"
threat_actors:              # optional
  - APT28                   # name, alias or group ID
layer_name: APT28 coverage  # optional
```

`latest` is the newest ATT&CK release supported by the converter's pinned dependencies. To pick up a new release, see the [converter README](.github/scripts/mitre_navigator/README.md#updating-dependencies).

Techniques used by the listed actors are highlighted. A technique's score is the number of listed actors that use it.

Running the converter locally is covered in its [README](.github/scripts/mitre_navigator/README.md).
