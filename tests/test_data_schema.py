"""Schema validation for data/keys.json and the data/history snapshots.

Catches silent corruption / schema drift in the auto-refreshed key data
(the update-keys workflow commits here every hour)."""
import json
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _snapshots():
    out = []
    kj = os.path.join(DATA, "keys.json")
    if os.path.exists(kj):
        out.append(kj)
    hist = os.path.join(DATA, "history")
    if os.path.isdir(hist):
        out += [os.path.join(hist, f) for f in os.listdir(hist) if f.endswith(".json")]
    return out


@pytest.mark.parametrize("path", _snapshots(), ids=lambda p: os.path.basename(p))
def test_snapshot_valid(path):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)                              # parses without error

    assert HEX64.match(d["version"]), f"bad version in {path}"
    for ts in ("last_checked", "last_updated"):
        assert isinstance(d.get(ts), str) and d[ts], f"missing {ts} in {path}"

    hsw = d.get("hsw")
    assert isinstance(hsw, dict), f"missing hsw block in {path}"
    assert hsw.get("cipher") == "AES-256-GCM", f"bad cipher in {path}"

    # request_key must always be present + verified; response_key may be null
    assert HEX64.match(hsw.get("request_key") or ""), f"bad request_key in {path}"
    assert hsw.get("verified") is True, f"not verified in {path}"
    rk = hsw.get("response_key")
    assert rk is None or HEX64.match(rk), f"bad response_key in {path}"

    for wire in ("request_wire", "response_wire"):
        assert "iv" in hsw.get(wire, ""), f"bad {wire} in {path}"


def test_current_keys_present():
    """data/keys.json must exist and name a current build."""
    kj = os.path.join(DATA, "keys.json")
    assert os.path.exists(kj), "data/keys.json is missing"
    with open(kj, encoding="utf-8") as f:
        d = json.load(f)
    assert HEX64.match(d["version"])
