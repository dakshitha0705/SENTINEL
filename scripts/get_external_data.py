"""Download the public attack recordings listed in data/external_catalog.json (run once while online).

    python -I scripts/get_external_data.py

Files go to data/public/<source>/ (git-ignored). They are treated as untrusted data: only parsed by
SENTINEL's ingestion, never executed. Zip archives are extracted flat (no path traversal).
"""
from __future__ import annotations

import json
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CATALOG = json.loads((ROOT / "data" / "external_catalog.json").read_text(encoding="utf-8"))
OUT = ROOT / "data" / "public"


def local_dir(rec) -> Path:
    name = Path(rec["path"]).name
    sub = "evtx_attack_samples" if rec["source"] == "evtx_attack_samples" else "otrf/" + name.removesuffix(".zip")
    return OUT / sub


def main():
    for rec in CATALOG["recordings"]:
        src = CATALOG["sources"][rec["source"]]
        d = local_dir(rec)
        d.mkdir(parents=True, exist_ok=True)
        target = d / Path(rec["path"]).name
        if not target.exists():
            url = src["base"] + urllib.parse.quote(rec["path"])
            print("downloading", rec["id"], rec["path"])
            with urllib.request.urlopen(url, timeout=120) as r:
                target.write_bytes(r.read())
        if target.suffix == ".zip":
            with zipfile.ZipFile(target) as z:
                for m in z.infolist():
                    dest = (d / Path(m.filename).name).resolve()
                    if m.is_dir() or dest.parent != d.resolve() or dest.exists():
                        continue
                    dest.write_bytes(z.read(m))
        print(rec["id"], "ok", target.stat().st_size, "bytes")


if __name__ == "__main__":
    sys.exit(main())
