"""Bidirectional local visualisation component (interactive 3D globe and attack graph).

The component is a static folder (static/viz) served by Streamlit itself: globe.gl (bundles three.js),
vis-network and Natural Earth country outlines are local files, so nothing is fetched from the internet.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import streamlit.components.v1 as components

_VIZ = components.declare_component("sentinel_viz", path=str(Path(__file__).parent / "static" / "viz"))


def _key(obj) -> str:
    return hashlib.sha1(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()[:16]


def globe(geo: dict, height: int = 560, selected: str | None = None, key: str = "globe", quality: str = "high"):
    """Render the globe. Returns the last interaction: {'type': 'marker'|'region'|'arc'|'clear', ...} or None."""
    args = {"kind": "globe", "mode": geo["mode"], "markers": geo["markers"], "arcs": geo["arcs"],
            "provenance": geo.get("provenance", ""), "height": height, "selected": selected, "quality": quality}
    args["data_key"] = _key([geo["mode"], geo["markers"], geo["arcs"], selected])
    return _VIZ(**args, key=key, default=None)


def graph(data: dict, height: int = 620, focus: str | None = None, key: str = "graph"):
    """Render the attack graph. Returns {'type': 'node', 'id': ...} after a click, else None."""
    args = {"kind": "graph", "nodes": data["nodes"], "edges": data["edges"], "height": height, "focus": focus}
    args["data_key"] = _key([data["nodes"], data["edges"], focus])
    return _VIZ(**args, key=key, default=None)
