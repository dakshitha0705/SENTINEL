"""Download public Windows security-log samples (OTRF Security-Datasets, MIT licence) for a sanity run.

Run once while online:  python -I scripts/get_public_data.py
Files land in data/public/otrf/<name>/ (git-ignored). Contents are treated as untrusted data:
they are only parsed by SENTINEL's ingestion, never executed.
"""
from __future__ import annotations

import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "public" / "otrf"
BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/"
FILES = ["empire_mimikatz_logonpasswords.zip", "psh_lsass_memory_dump_comsvcs.zip"]


def main():
    for name in FILES:
        target = OUT / name.removesuffix(".zip")
        target.mkdir(parents=True, exist_ok=True)
        zpath = target / name
        if not zpath.exists():
            print("downloading", name)
            with urllib.request.urlopen(BASE + name, timeout=120) as r:
                zpath.write_bytes(r.read())
        with zipfile.ZipFile(zpath) as z:
            for m in z.infolist():
                dest = (target / Path(m.filename).name).resolve()
                if dest.parent != target.resolve() or m.is_dir():
                    continue  # no path traversal, flat extraction only
                if not dest.exists():
                    dest.write_bytes(z.read(m))
        print(name, "->", [p.name for p in target.iterdir()])


if __name__ == "__main__":
    sys.exit(main())
