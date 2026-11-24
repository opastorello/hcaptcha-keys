"""Fully-local, self-verifying HSW master-key extraction.

Recovers the per-build AES-256 ``request_key`` and ``response_key`` straight
from the live hCaptcha bundle using ONLY hCaptcha's own freely-downloaded
code -- no third-party key feed (no vastien, no CircuitSavage), no network
beyond fetching the bundle from the hCaptcha asset server.

Method: **fixslice bitslice write interception + module oracle**
================================================================
The bundle's AES is RustCrypto ``fixslice32``. The round-key schedule is not
readable from linear memory (it is deobfuscated on-demand, per 4-byte read).
But the schedule is *written* to that obfuscated store through virtual-memory
WRITER functions of the shape ``writer(base, value, offset)`` where
``addr = base + offset`` and ``value`` is the **plaintext** word (the writer
XORs it with the page mask before storing). So we splice a capture prologue
into the ``u32`` writer, record every ``(addr, value)`` it writes during a
gated ``hsw(1)`` / ``hsw(0)`` call, reassemble the contiguous 120-word fixslice
schedule in the clear, and invert it to the 32-byte master:

    M[:16] = inv_bitslice(rk0)
    M[16:] = inv_bitslice(undo sub_bytes_nots + shift_rows_1 of rk1)

Every candidate is then **self-verified** by rebuilding the full 120-word
schedule from the recovered master and requiring an exact match, and
**oracle-verified** against the bundle's own output (a wrong key cannot pass
either gate -- nothing is fabricated).

Build-robustness
================
Function indices rotate several times a day. Everything here is found by
structural fingerprint only (the 320-byte page arithmetic + ``i32.store8`` for
writers; the fixslice masks for the key schedule), never by hard-coded index,
so it survives a build rotation without edits.
"""
from __future__ import annotations

import base64
import hashlib
import os
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

import requests
from Crypto.Cipher import AES

from . import version as _v
from .tools.wasm_disasm import WasmModule
from .tools.wasm_writer import ModuleWriter, encode_uleb, encode_sleb
from .tools.js_runtime import JsRuntime
from .tools import fixslice as _fs
from .tools.sandbox_hook import HOOK_JS as _HOOK_JS
from .hsw_bridge import HSWAnalyzer
from .hsw_n_token_decrypt import _find_fixslice_ks_funcs

NWRK = 120
_PT = bytes([0x41] * 32)
_WIRE = "iv(12) || ct(N) || tag(16)"
_METHOD = "fixslice bitslice write interception + module oracle"

# scratch layout (well inside the >=1.2MB linear memory)
_GATE = 590_016
_COUNTER = 590_000
_SCRATCH = 600_000
_MAX = 8000


@dataclass
class BuildKeys:
    version: str
    request_key: Optional[bytes] = None
    response_key: Optional[bytes] = None
    cipher: str = "AES-256-GCM"
    request_wire: str = _WIRE
    response_wire: str = _WIRE
    functions: dict = field(default_factory=dict)
    wasm_sha256: str = ""
    bundle_sha256: str = ""
    bundle_sri: str = ""

    @property
    def verified(self) -> bool:
        return self.request_key is not None


def _c(n: int) -> bytes:
    return b"\x41" + encode_sleb(n)


def find_u32_writer(mod) -> Optional[int]:
    """Structurally locate the u32 virtual-memory writer: sig
    ``(i32, i32, i32) -> []``, body uses the 320-byte page arithmetic
    (``i32.const 320`` + ``div_u`` + ``rem_u``) and emits the most
    ``i32.store8`` (a u32 write = 4 bytes, the widest i32-value writer)."""
    best, best_st = None, 0
    for f in mod.functions:
        params, results = mod.types[f["type_idx"]]
        if results != [] or params != ["i32", "i32", "i32"]:
            continue
        instrs = mod.decode_function(f["func_idx"]) or []
        consts = {o[0] for n, o, _, _ in instrs if n == "i32.const" and o}
        names = {n for n, _, _, _ in instrs}
        if 320 not in consts or "i32.div_u" not in names or "i32.rem_u" not in names:
            continue
        st = sum(1 for n, _, _, _ in instrs if n == "i32.store8")
        if st > best_st:
            best, best_st = f["func_idx"], st
    return best


def _invert_schedule(rk: List[int]) -> Optional[bytes]:
    """120 captured fixslice round-key words -> 32-byte master, iff the
    rebuilt schedule reproduces all 120 words exactly."""
    if len(rk) < NWRK or not any(rk[:16]):
        return None
    try:
        a, _ = _fs.inv_bitslice(list(rk[0:8]))
        ch = list(rk[8:16]); _fs.sub_bytes_nots(ch); _fs.shift_rows_1(ch)
        cc, _ = _fs.inv_bitslice(ch)
        master = a + cc
        if _fs.aes256_key_schedule(master)[:NWRK] == rk[:NWRK]:
            return master
    except Exception:
        pass
    return None


def _runs_masters(by_addr: dict, out: list) -> None:
    addrs = sorted(by_addr)
    if not addrs:
        return
    runs, cur = [], [addrs[0]]
    for a in addrs[1:]:
        if a == cur[-1] + 4:
            cur.append(a)
        else:
            runs.append(cur); cur = [a]
    runs.append(cur)
    for run in runs:
        if len(run) < NWRK:
            continue
        words = [by_addr[a] for a in run]
        for off in range(0, len(words) - NWRK + 1):
            m = _invert_schedule(words[off:off + NWRK])
            if m is not None and m not in out:
                out.append(m)


def _masters_from_stream(stream: List[tuple]) -> List[bytes]:
    """Every schedule-verified master in a (addr, value) write stream.

    The key schedule is written as a burst, but the same scratch addresses are
    later reused for AES state, so a plain last-value map can corrupt it. We
    union three reconstructions: last-value-per-addr, first-value-per-addr, and
    ordered bursts of 120 consecutive stride-4 writes.
    """
    if not stream:
        return []
    out: List[bytes] = []
    by_last, by_first = {}, {}
    for addr, val in stream:
        v = val & 0xFFFFFFFF
        by_last[addr] = v
        if addr not in by_first:
            by_first[addr] = v
    _runs_masters(by_last, out)
    _runs_masters(by_first, out)
    for i in range(0, max(0, len(stream) - NWRK + 1)):
        a0 = stream[i][0]
        if all(stream[i + k][0] == a0 + 4 * k for k in range(NWRK)):
            m = _invert_schedule([stream[i + k][1] & 0xFFFFFFFF for k in range(NWRK)])
            if m is not None and m not in out:
                out.append(m)
    return out


def _gcm_decrypt(key: bytes, blob: bytes) -> Optional[bytes]:
    """GCM-decrypt an ``iv(12) || ct || tag(16)`` blob; None on failure."""
    if len(blob) < 28:
        return None
    iv, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    try:
        return AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)
    except Exception:
        return None


def _gcm_blob(key: bytes, pt: bytes) -> bytes:
    iv = os.urandom(12)
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=iv).encrypt_and_digest(pt)
    return iv + ct + tag


def extract_build_keys(version: Optional[str] = None,
                       timeout: float = 90.0) -> Optional[BuildKeys]:
    """Extract + verify this build's request/response AES-256 keys locally.

    Returns a :class:`BuildKeys` (``request_key`` always set on success,
    ``response_key`` set when the response schedule was captured), or ``None``
    if the writer could not be found / no schedule verified.
    """
    version = version or _v.latest_version()
    info = HSWAnalyzer(version).analyze()
    wasm = bytes.fromhex(info["wasm_bytes_hex"])
    mod = WasmModule(wasm)

    u32w = find_u32_writer(mod)
    if u32w is None:
        return None

    writer = ModuleWriter(mod)
    pro = bytearray()
    pro += _c(_GATE) + b"\x28\x02\x00" + b"\x04\x40"                      # if *GATE:
    pro += _c(_COUNTER) + b"\x28\x02\x00" + _c(_MAX) + b"\x49" + b"\x04\x40"  # if *cnt<MAX:
    pro += _c(_SCRATCH) + _c(_COUNTER) + b"\x28\x02\x00" + _c(8) + b"\x6c" + b"\x6a"
    pro += b"\x20\x00" + b"\x20\x02" + b"\x6a" + b"\x36\x02\x00"          # [dst]=a0+a2
    pro += _c(_SCRATCH) + _c(_COUNTER) + b"\x28\x02\x00" + _c(8) + b"\x6c" + b"\x6a" + _c(4) + b"\x6a"
    pro += b"\x20\x01" + b"\x36\x02\x00"                                  # [dst+4]=a1
    pro += _c(_COUNTER) + _c(_COUNTER) + b"\x28\x02\x00" + b"\x41\x01\x6a" + b"\x36\x02\x00"
    pro += b"\x0b\x0b"
    writer.code.splice_code(u32w, 0, n_replace=0, new_bytes=bytes(pro))

    t_pk = next((i for i, (p, r) in enumerate(mod.types) if p == ["i32"] and r == ["i32"]), None) \
        or writer.add_type(["i32"], ["i32"])
    t_po = next((i for i, (p, r) in enumerate(mod.types) if p == ["i32", "i32"] and r == []), None) \
        or writer.add_type(["i32", "i32"], [])
    writer.add_function(t_pk, [], bytes([0x20, 0x00, 0x28, 0x02, 0x00, 0x0b]), export_name="__peek32")
    writer.add_function(t_po, [], bytes([0x20, 0x00, 0x20, 0x01, 0x36, 0x02, 0x00, 0x0b]), export_name="__poke32")
    patched = writer.emit()

    rt = JsRuntime()
    try:
        rt.eval(f"globalThis.__patched_wasm_b64='{base64.b64encode(patched).decode()}';")
        rt.eval(_HOOK_JS)
        r = requests.get(_v.asset_url(version, "hsw.js")); r.encoding = "utf-8"
        bundle_text = r.text
        rt.eval(bundle_text, suppress=True)
        rt.eval("(async()=>{try{await window.hsw(1,new Uint8Array(0));}catch(e){}})();", suppress=True)
        for _ in range(80):
            time.sleep(0.1)
            if rt.eval("globalThis.__hsw_exports") is not None:
                break
        if rt.eval("globalThis.__hsw_exports") is None:
            return None

        def run_capture(js_call: str) -> tuple:
            rt.eval(f"""globalThis.__done=0;globalThis.__blob=null;(async()=>{{
                const e=globalThis.__hsw_exports;
                e.__poke32({_COUNTER},0); e.__poke32({_GATE},1);
                try{{ {js_call} }}catch(ex){{globalThis.__e=String(ex);}}
                finally{{e.__poke32({_GATE},0);}} globalThis.__done=1;}})();""",
                    suppress=True)
            for _ in range(int(timeout * 4)):
                if rt.eval("globalThis.__done"):
                    break
                time.sleep(0.25)
            n = (rt.eval(f"globalThis.__hsw_exports.__peek32({_COUNTER})") or 0) & 0xFFFFFFFF
            n = min(n, _MAX)
            data = rt.eval(f"(function(){{return Array.from(new Uint8Array("
                           f"globalThis.__hsw_memory.buffer,{_SCRATCH},{n*8}));}})()") or []
            recs = struct.unpack(f"<{2*n}I", bytes(data)) if n else ()
            blob = rt.eval("globalThis.__blob")
            blob = bytes(blob) if blob else b""
            return list(zip(recs[0::2], recs[1::2])), blob

        def hsw0_returns_pt(key: bytes) -> bool:
            """Oracle check: hsw(0, iv||GCM(key,iv,pt)||tag) returns pt."""
            vb = _gcm_blob(key, _PT)
            rt.eval(f"""globalThis.__rd=0;globalThis.__rv=null;(async()=>{{
                try{{const b=new Uint8Array([{",".join(str(x) for x in vb)}]);
                  const o=await window.hsw(0,b);
                  globalThis.__rv=o?Array.from(o):null;}}catch(e){{}}
                globalThis.__rd=1;}})();""", suppress=True)
            for _ in range(120):
                if rt.eval("globalThis.__rd"):
                    break
                time.sleep(0.25)
            rv = rt.eval("globalThis.__rv")
            return bool(rv and bytes(rv) == _PT)

        # Phase A: request key (encrypt_req_data). The one that GCM-decrypts
        # the bundle's own encrypt output is the confirmed request key.
        req_js = ("const p=new Uint8Array(32);for(let i=0;i<32;i++)p[i]=0x41;"
                  "globalThis.__blob=Array.from(await window.hsw(1,p));")
        req_stream, enc_blob = run_capture(req_js)
        request_key = next((m for m in _masters_from_stream(req_stream)
                            if _gcm_decrypt(m, enc_blob) == _PT), None)

        # Phase B: response key (decrypt_resp_data). Feed a crafted blob so
        # hsw(0) schedules its key (MAC may fail; the schedule is still written).
        # Accept the verified master that round-trips through hsw(0).
        response_key = None
        if request_key is not None:
            probe = _gcm_blob(request_key, _PT)
            probe_js = ("const b=new Uint8Array([" + ",".join(str(x) for x in probe) + "]);"
                        "try{await window.hsw(0,b);}catch(_e){}")
            resp_stream, _ = run_capture(probe_js)
            cands = _masters_from_stream(resp_stream)
            # prefer a master distinct from the request key, then fall back
            for cand in sorted(cands, key=lambda m: m == request_key):
                if hsw0_returns_pt(cand):
                    response_key = cand
                    break
    finally:
        try:
            rt.close()
        except Exception:
            pass

    if request_key is None:
        return None

    bundle_bytes = bundle_text.encode("utf-8", "surrogatepass")
    bk = BuildKeys(
        version=version,
        request_key=request_key,
        response_key=response_key,
        functions={
            "u32_writer": u32w,
            "fixslice_functions": _find_fixslice_ks_funcs(mod),
        },
        wasm_sha256=info.get("wasm_sha256", hashlib.sha256(wasm).hexdigest()),
        bundle_sha256=hashlib.sha256(bundle_bytes).hexdigest(),
        bundle_sri="sha256-" + base64.b64encode(hashlib.sha256(bundle_bytes).digest()).decode(),
    )
    return bk


# ---------------------------------------------------------------------------
# vastien-compatible JSON serialisation
# ---------------------------------------------------------------------------
def build_keys_json(bk: BuildKeys) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"
    hsw = {
        "cipher": bk.cipher,
        "request_key": bk.request_key.hex() if bk.request_key else None,
        "request_wire": bk.request_wire,
        "response_key": bk.response_key.hex() if bk.response_key else None,
        "response_wire": bk.response_wire,
        "verified": bk.verified,
        "verification": (
            "request_key: GCM-decrypting hsw(1, pt) under it returns pt. "
            "response_key: hsw(0, iv||GCM(key,iv,pt)||tag) returns pt. "
            "Both checked against this build's own WASM module."
        ),
        "extraction_method": _METHOD,
        "bundle_sri": bk.bundle_sri,
        "bundle_sha256": bk.bundle_sha256,
        "wasm_sha256": bk.wasm_sha256,
        "functions": bk.functions,
        "extracted_at": now,
    }
    return {
        "version": bk.version,
        "last_checked": now,
        "last_updated": now,
        "hsw": hsw,
    }


if __name__ == "__main__":
    import json, sys
    ver = sys.argv[1] if len(sys.argv) > 1 else None
    bk = extract_build_keys(ver)
    if bk is None:
        print("extraction failed (no verified key on this build)")
        sys.exit(1)
    print(json.dumps(build_keys_json(bk), indent=2))
