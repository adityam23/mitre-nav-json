"""Build ATT&CK Navigator layer documents with mitreattack-python's navlayers."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from mitreattack.navlayers import Layer as NavigatorLayer
from mitreattack.navlayers.core.versions import Versions

from .stix import AttackDataset, ThreatActor

ACTOR_TECHNIQUE_COLOR = "#ff0000"

Layer = dict[str, Any]


class LayerBuildError(RuntimeError):
    """Raised when navlayers rejects the generated layer."""


def default_layer_name(dataset: AttackDataset, actors: Sequence[ThreatActor]) -> str:
    if actors:
        return f"{', '.join(a.name for a in actors)} ({dataset.domain})"
    return f"{dataset.domain} v{dataset.attack_version}"


def build_layer(dataset: AttackDataset, actors: Sequence[ThreatActor], *, name: str | None = None) -> Layer:
    """List every technique in the dataset; techniques used by any of ``actors`` are colored red."""
    users_by_technique: dict[str, list[str]] = {}
    parents_with_highlighted_subs: set[str] = set()
    for actor in actors:
        for technique in dataset.techniques_used_by(actor):
            users_by_technique.setdefault(technique.attack_id, []).append(actor.name)
            if technique.is_subtechnique:
                parents_with_highlighted_subs.add(technique.parent_attack_id)

    techniques = []
    for technique in dataset.techniques:
        entry: dict[str, Any] = {
            "techniqueID": technique.attack_id,
            "enabled": True,
            "showSubtechniques": technique.attack_id in parents_with_highlighted_subs,
        }
        if users := users_by_technique.get(technique.attack_id):
            entry.update(score=1, color=ACTOR_TECHNIQUE_COLOR, comment=f"Used by: {', '.join(users)}")
        techniques.append(entry)

    legend_items = []
    if actors:
        legend_items.append(
            {"label": f"Used by {', '.join(a.name for a in actors)}", "color": ACTOR_TECHNIQUE_COLOR}
        )

    layer = NavigatorLayer(
        {
            "name": name or default_layer_name(dataset, actors),
            "domain": dataset.domain,
            # Layer and Navigator versions are the defaults of the installed navlayers schema.
            "versions": Versions(attack=dataset.attack_version.split(".", 1)[0]),
            "description": _describe(dataset, actors),
            "layout": {"showID": True},
            "techniques": techniques,
            "legendItems": legend_items,
            "metadata": [{"name": "threat_actor", "value": f"{a.name} ({a.attack_id})"} for a in actors],
        }
    ).to_dict()
    if layer is None:
        raise LayerBuildError(f"navlayers rejected the layer for {dataset.domain} v{dataset.attack_version}")
    return layer


def _describe(dataset: AttackDataset, actors: Sequence[ThreatActor]) -> str:
    description = f"Generated from MITRE ATT&CK {dataset.domain} v{dataset.attack_version}."
    if actors:
        refs = ", ".join(f"{a.name} ({a.attack_id})" for a in actors)
        description += f" Techniques used by {refs}, directly or via attributed campaigns, are highlighted in red."
    return description
