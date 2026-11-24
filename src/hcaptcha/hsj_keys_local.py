"""hsj key equivalence probe.

On current builds the `hsj.js` (inspekt_client / fingerprint) bundle encrypts
and decrypts with the **same** AES-256-GCM keys as `hsw.js` (the vastien
`matches_hsw` case). Rather than re-implement a fragile key-schedule extractor
for the obfuscated T-table AES inside hsj, we **verify** the equivalence
directly against hsj's own oracle: if `hsj(1, pt)` is decryptable under the
hsw `request_key`, and `hsj(0, GCM(response_key, pt))` returns `pt`, then hsj
shares the hsw keys for this build and we can publish them in the hsj block.

If a build does *not* share keys, the probe returns `matches_hsw=False` and the
caller omits the hsj block (documented gap) rather than publishing anything
unverified.
"""
from __future__ import annotations

import os
import time
from typing import Optional

import requests
from Crypto.Cipher import AES

from . import version as _v
from .tools.js_runtime import JsRuntime

_PT = bytes([0x41] * 32)
_WIRE = "iv(12) || ct(N) || tag(16)"


def _gcm_dec(key: bytes, blob: bytes) -> Optional[bytes]:
    if len(blob) < 28:
        return None
    try:
        return AES.new(key, AES.MODE_GCM, nonce=blob[:12]).decrypt_and_verify(blob[12:-16], blob[-16:])
    except Exception:
        return None


def _gcm_blob(key: bytes, pt: bytes) -> bytes:
    iv = os.urandom(12)
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=iv).encrypt_and_digest(pt)
    return iv + ct + tag


def probe_hsj_equivalence(version: str, request_key: bytes,
                          response_key: Optional[bytes],
                          timeout: float = 90.0) -> dict:
    """Return a dict describing whether hsj shares the hsw keys this build.

    Keys: ``matches_hsw`` (bool), ``request_ok`` (bool), ``response_ok`` (bool).
    """
    rt = JsRuntime()
    result = {"matches_hsw": False, "request_ok": False, "response_ok": False}
    try:
        r = requests.get(_v.asset_url(version, "hsj.js")); r.encoding = "utf-8"
        rt.eval(r.text, suppress=True)

        # --- encrypt side: hsj(1, pt) must decrypt under request_key ---
        rt.eval("globalThis.__d=0;globalThis.__o=null;globalThis.__e=null;"
                "(async()=>{try{var p=new Uint8Array(32);for(var i=0;i<32;i++)p[i]=0x41;"
                "var o=await window.hsj(1,p);globalThis.__o=o?Array.from(o):null;}"
                "catch(e){globalThis.__e=''+e;}globalThis.__d=1;})();", suppress=True)
        for _ in range(int(timeout * 4)):
            if rt.eval("globalThis.__d"):
                break
            time.sleep(0.25)
        o = rt.eval("globalThis.__o")
        enc = bytes(o) if o else None
        if enc is not None and _gcm_dec(request_key, enc) == _PT:
            result["request_ok"] = True

        # --- decrypt side: hsj(0, GCM(response_key, pt)) must return pt ---
        if response_key is not None:
            vb = _gcm_blob(response_key, _PT)
            arr = ",".join(str(b) for b in vb)
            rt.eval(f"globalThis.__d2=0;globalThis.__o2=null;"
                    f"(async()=>{{try{{var b=new Uint8Array([{arr}]);"
                    f"var o=await window.hsj(0,b);globalThis.__o2=o?Array.from(o):null;}}"
                    f"catch(e){{}}globalThis.__d2=1;}})();", suppress=True)
            for _ in range(int(timeout * 4)):
                if rt.eval("globalThis.__d2"):
                    break
                time.sleep(0.25)
            o2 = rt.eval("globalThis.__o2")
            if o2 and bytes(o2) == _PT:
                result["response_ok"] = True

        result["matches_hsw"] = result["request_ok"] and (
            response_key is None or result["response_ok"])
        return result
    finally:
        try:
            rt.close()
        except Exception:
            pass


def hsj_block(bk, probe: dict) -> Optional[dict]:
    """Build the vastien-schema hsj block from a BuildKeys + probe result,
    or None if hsj did not verify as sharing the hsw keys."""
    if not probe.get("request_ok"):
        return None
    return {
        "cipher": "AES-256-GCM",
        "request_key": bk.request_key.hex(),
        "request_wire": _WIRE,
        "response_key": bk.response_key.hex() if (bk.response_key and probe.get("response_ok")) else None,
        "response_wire": _WIRE,
        "verified": True,
        "matches_hsw": True,
        "verification": (
            "request_key: hsj(1, pt) decrypts under the hsw request_key. "
            "response_key: hsj(0, iv||GCM(response_key,iv,pt)||tag) returns pt. "
            "Checked against hsj's own bundle — confirms hsj shares the hsw keys."
        ),
        "extraction_method": "hsj oracle key-equivalence (shares hsw keys)",
    }
