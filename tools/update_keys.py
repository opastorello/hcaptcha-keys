#!/usr/bin/env python
"""CI runner -- keep an auto-updating key repo up to date, fully independently.

Detects the current hCaptcha build, and:
  * same build as data/keys.json  -> just bump ``last_checked`` (heartbeat).
  * new build                     -> extract + verify both AES-256 keys with
    the local write-interception extractor and write data/keys.json +
    data/history/<version>.json in a stable published schema.

Prints a machine-readable status line on stdout for the workflow to turn into
a commit message:
    UNCHANGED <version>
    NEWBUILD  <version>
    FAILED    <version>
Exit code is 0 for UNCHANGED/NEWBUILD, 1 for FAILED (so the workflow can retry).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, "src")

from hcaptcha import version as _v
from hcaptcha.hsw_keys_local import extract_build_keys, build_keys_json


def iso_now() -> str:
    n = datetime.now(timezone.utc)
    return n.strftime("%Y-%m-%dT%H:%M:%S.") + f"{n.microsecond // 1000:03d}Z"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="data")
    ap.add_argument("--version", default=None,
                    help="pin a build hash (default: current live build)")
    args = ap.parse_args()

    os.makedirs(os.path.join(args.data_dir, "history"), exist_ok=True)
    keys_path = os.path.join(args.data_dir, "keys.json")

    version = args.version or _v.latest_version()
    existing = None
    if os.path.exists(keys_path):
        try:
            with open(keys_path, encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = None

    now = iso_now()

    # Same build -> heartbeat only.
    if existing and existing.get("version") == version:
        existing["last_checked"] = now
        if isinstance(existing.get("hsw"), dict):
            existing["hsw"]["last_checked"] = now
        with open(keys_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, indent=2)
            f.write("\n")
        print(f"UNCHANGED {version}")
        return 0

    # New build -> extract + verify.
    print(f"new build {version[:12]} -- extracting...", file=sys.stderr)
    bk = extract_build_keys(version)
    if bk is None or bk.request_key is None:
        print(f"FAILED {version}")
        return 1

    doc = build_keys_json(bk)
    hist_path = os.path.join(args.data_dir, "history", f"{version}.json")
    for path in (keys_path, hist_path):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2)
            f.write("\n")

    rk = bk.request_key.hex()[:16]
    sk = (bk.response_key.hex()[:16] if bk.response_key else "none")
    print(f"extracted req={rk}.. resp={sk}..", file=sys.stderr)
    print(f"NEWBUILD {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
