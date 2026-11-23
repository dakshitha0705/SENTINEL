"""Attack-graph adapter: nodes and edges come only from correlation output.

Nodes: incidents, alerts (detections), and the users / hosts / source IPs named by those alerts.
Edges:
* incident -> alert   ("contains"; dashed when the alert is context-only)
* alert -> entity     ("involves": the alert's own users/hosts/IPs)
* alert -> alert      ("link": the Storyline Engine's link, with its strength and reason)
No edge is inferred by the UI.
"""
from __future__ import annotations

SEV_FILL = {"Critical": "#B98780", "High": "#C8AA7C", "Medium": "#819B8D", "Low": "#6F8482"}
TYPE_FILL = {"user": "#E8DDC9", "host": "#A7BFAF", "ip": "#9A8F80", "alert": "#5E7A6F"}


def build(analysis, incidents, include=("user", "host", "ip"), include_context=True) -> dict:
    nodes, edges, seen = [], [], set()

    def node(nid, label, ntype, title, color=None):
        if nid in seen:
            return
        seen.add(nid)
        nodes.append({"id": nid, "label": label, "type": ntype, "title": title,
                      "color": color or TYPE_FILL.get(ntype)})

    for inc in incidents:
        lv = inc["severity"]["level"]
        iid = inc["incident_id"]
        node(iid, iid, "incident", f"{iid} - {lv} {inc['severity']['score']}\n{inc['title']}", SEV_FILL[lv])
        for aid in inc["alert_ids"]:
            a = analysis.alerts_by_id[aid]
            if a["context"] and not include_context:
                continue
            node(aid, a["rule"], "alert", f"{aid} {a['rule']} {a['name']}\n{a['reason'][:220]}")
            edges.append({"from": iid, "to": aid, "kind": "context" if a["context"] else "contains",
                          "title": f"{iid} contains {aid} ({inc['membership'][aid]})",
                          "strength": inc["membership"][aid]})
            for kind, key, prefix in (("user", "users", "U:"), ("host", "hosts", "H:"), ("ip", "ips", "IP:")):
                if kind not in include:
                    continue
                for v in a[key]:
                    node(prefix + v, v, kind, f"{kind}: {v}")
                    edges.append({"from": aid, "to": prefix + v, "kind": "involves", "title": f"{aid} involves {v}"})
        for l in inc["links"]:
            if l["from"] in seen and l["to"] in seen:
                edges.append({"from": l["from"], "to": l["to"], "kind": "link", "strength": l["strength"],
                              "title": f"{l['strength']} link: {l['reason']}"})
    return {"nodes": nodes, "edges": edges}


def node_details(analysis, node_id: str) -> dict:
    """What a clicked node refers to, resolved against the analysis (never against the browser data)."""
    if node_id.startswith("INC-"):
        inc = next((i for i in analysis.incidents if i["incident_id"] == node_id), None)
        return {"type": "incident", "incident": inc}
    if node_id.startswith("ALR-"):
        a = analysis.alerts_by_id.get(node_id)
        incs = [i["incident_id"] for i in analysis.incidents if node_id in i["alert_ids"]]
        return {"type": "alert", "alert": a, "incidents": incs}
    for prefix, col, kind in (("U:", "user", "user"), ("H:", "host", "host"), ("IP:", "src_ip", "ip")):
        if node_id.startswith(prefix):
            v = node_id[len(prefix):]
            ev = analysis.events
            mask = ev[col] == v
            if kind == "user":
                mask |= (ev["actor"] == v) | (ev["target_user"] == v)
            incs = [i["incident_id"] for i in analysis.incidents
                    if v in i[{"user": "users", "host": "hosts", "ip": "ips"}[kind]]]
            return {"type": kind, "value": v, "events": ev[mask], "incidents": incs}
    return {"type": "unknown"}
