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

    def _check_block(block, name):
        assert isinstance(block, dict), f"missing {name} block in {path}"
        assert block.get("cipher") == "AES-256-GCM", f"bad cipher in {name} of {path}"
        # request_key must be present + verified; response_key may be null
        assert HEX64.match(block.get("request_key") or ""), f"bad request_key in {name} of {path}"
        assert block.get("verified") is True, f"{name} not verified in {path}"
        rk = block.get("response_key")
        assert rk is None or HEX64.match(rk), f"bad response_key in {name} of {path}"
        for wire in ("request_wire", "response_wire"):
            assert "iv" in block.get(wire, ""), f"bad {wire} in {name} of {path}"

    _check_block(d.get("hsw"), "hsw")          # hsw always present
    if d.get("hsj") is not None:               # hsj present when it shares hsw keys
        _check_block(d["hsj"], "hsj")


def test_current_keys_present():
    """data/keys.json must exist and name a current build."""
    kj = os.path.join(DATA, "keys.json")
    assert os.path.exists(kj), "data/keys.json is missing"
    with open(kj, encoding="utf-8") as f:
        d = json.load(f)
    assert HEX64.match(d["version"])
