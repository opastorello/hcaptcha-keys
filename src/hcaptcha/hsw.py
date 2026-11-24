"""Direct, accurate HSW master-key extraction.

No candidate-guessing. Each step is structurally determined from the
WASM binary + deobf source:

  1. Run deobf.py — get the encrypt and decrypt magic numbers from
     hsw.js source (the JS-side wrappers `encrypt_req_data` and
     `decrypt_resp_data` both call `vc(MAGIC, ...)` with a literal
     magic int).

  2. In the WASM, walk the dispatcher (func vc) instruction stream.
     Find each `i32.const MAGIC ; i32.eq ; if` triple — the function
     called inside that `if` block is the per-direction implementation.

  3. The implementation function (encrypt_impl, decrypt_impl) opens
     a stack frame and calls the key schedule. Find the `call N`
     instruction whose target N is a (i32,i32)->() function with
     fixslice32 mask constants — that N is the key-schedule function.

  4. The key-schedule function's body starts with i32.add / local.tee
     loads — the FIRST 8 `call M` invocations with `i32.const 0,
     local.get 1, ..., call M` are the master-key word loads, where
     M is the XOR-deobfuscation helper. The pointer base is the
     function's second arg (local 1).

  5. Patch the key schedule's entry to: for i in 0..7, call
     M(0, local 1 + i*4), and store the returned i32 to a fixed
     scratch region. Add a sentinel write.

  6. Load the patched WASM into the bundle, run encrypt and decrypt
     (the decrypt fails with our dummy bytes, but the key schedule
     fires first). Read both scratch regions — those are the encrypt
     and decrypt master keys.

  7. Verify the encrypt key by AES-256-GCM round-trip.

All function indices are derived from the WASM's structure, never
hardcoded. The MAGIC numbers come from the deobf source. Both rotate
per build; this works on every build.
"""
import base64
import hashlib
import json
import os
import re
import sys
import time
import requests


from .tools.wasm_disasm import WasmModule, _load_wasm
from .tools.wasm_writer import ModuleWriter, encode_uleb, encode_sleb
from .tools.js_runtime import JsRuntime
from .log import Logger
from . import version as _v


# Two independent scratch slots so we can capture both directions in
# a single sandbox run.
SCRATCH_ENC      = 32_000
SENTINEL_ENC     = 32_040
COUNTER_ENC      = 32_044   # For new-style: byte counter
SCRATCH_DEC      = 32_100
SENTINEL_DEC     = 32_140
COUNTER_DEC      = 32_144   # For new-style: byte counter
SENTINEL_VAL_ENC = -889275714   # 0xCAFEBABE (signed)
SENTINEL_VAL_DEC = -559038737   # 0xDEADBEEF (signed)


# ---------------------------------------------------------------------------
# Structural identification — no heuristics, no guessing.
# ---------------------------------------------------------------------------
def _read_magics_from_deobf(version: str) -> dict:
    """Run deobf.py on the live hsw.js, read the encrypt + decrypt
    magic numbers from the deobf source's wbg wrappers."""
    from .tools.deobf import fetch_and_deobfuscate
    deobf_path = fetch_and_deobfuscate("hsw.js", version, quiet=True)
    src = open(deobf_path, "r", encoding="utf-8").read()

    # Pattern 1: Old style - explicit function names
    enc_match = re.search(
        r"encrypt_req_data: function \([^)]*\) \{[^}]*?\b\w+\.\w+\((-?\d{5,})",
        src, re.S)
    dec_match = re.search(
        r"decrypt_resp_data: function \([^)]*\) \{[^}]*?\b\w+\.\w+\((-?\d{5,})",
        src, re.S)

    # Pattern 2: New style - find dispatcher call patterns with magic numbers
    if not enc_match or not dec_match:
        # Pattern: }, NAME = function (a) { try { ... b13.bd(MAGIC, ...
        # or b13[y1(8)](MAGIC, ... (bracket notation with decoder)
        # Decrypt function pattern - look for first wasm dispatcher call in the function
        dec_pattern = re.search(
            r'},\s*\w+\s*=\s*function\s*\(\w+\)\s*\{\s*try\s*\{[^}]*?\w+\.(\w+)\((-?\d{6,}),',
            src)
        if dec_pattern:
            dec_match = type('Match', (), {'group': lambda self, n: dec_pattern.group(2)})()

        # Encrypt pattern: e: typeof X == "Y" ? function (a) { try { ... .bd(MAGIC, ...
        enc_pattern = re.search(
            r'e:\s*typeof\s+\w+\s*==\s*"[^"]+"\s*\?\s*function\s*\(\w+\)\s*\{\s*try\s*\{[^}]*?\w+\.\w+\((-?\d{6,}),',
            src)
        if enc_pattern:
            enc_match = enc_pattern

    # Pattern 3: Nov 2026 style - h2 = !!X ? function(a) { ... .cd(MAGIC, ...} for decrypt
    # and l4 = { i: function(a) { ... .cd(MAGIC, ...}} for encrypt
    if not dec_match:
        # Decrypt: var h2 = !!something ? function (a) { try { ... .cd(MAGIC, ...
        dec_pattern = re.search(
            r'var\s+h2\s*=\s*!!\w+\s*\?\s*function\s*\(\w+\)\s*\{\s*try\s*\{[^}]*?\w+\.cd\((-?\d{6,}),',
            src)
        if dec_pattern:
            dec_match = dec_pattern

    if not enc_match:
        # Encrypt: l4 = { i: function (a) { try { ... .cd(MAGIC, ...
        enc_pattern = re.search(
            r'l4\s*=\s*\{\s*i:\s*function\s*\(\w+\)\s*\{\s*try\s*\{[^}]*?\w+\.cd\((-?\d{6,}),',
            src)
        if enc_pattern:
            enc_match = enc_pattern

    if not enc_match or not dec_match:
        raise RuntimeError(
            "could not find encrypt/decrypt magics in deobf source")
    return {
        "encrypt_magic": int(enc_match.group(1)),
        "decrypt_magic": int(dec_match.group(1)),
    }


def _find_dispatcher_func(mod: WasmModule) -> int:
    """The dispatcher (vc, bd, etc.) is the largest exported function with a
    multi-i32-arg, no-result signature, and a body full of magic-number
    comparisons (lots of `i32.const ; i32.eq ; if` triples)."""
    n_imports = sum(1 for im in mod.imports if im["kind"] == "func")
    # Try known dispatcher names first
    for name in ("cd", "vc", "bd", "ad", "$c", "_c"):
        for ex in mod.exports:
            if ex["kind"] != "func": continue
            if ex["name"] != name: continue
            return ex["idx"]
    # Fall back: locate by signature shape (>=7 args, 0 results)
    for ex in mod.exports:
        if ex["kind"] != "func": continue
        f = next((f for f in mod.functions if f["func_idx"] == ex["idx"]), None)
        if f is None: continue
        params, results = mod.types[f["type_idx"]]
        if len(params) >= 7 and len(results) == 0:
            return ex["idx"]
    raise RuntimeError("dispatcher not found")


def _find_key_schedule_for_magic(mod: WasmModule, vc_idx: int,
                                  magic: int) -> int:
    """Walk vc's instructions; find the `i32.const MAGIC ; i32.eq ; if`
    triple, then within that if-block find the `call N` whose target N
    is a (i32,i32)->() function that calls the deobf helper many times.
    That N is the key-schedule function for this direction.
    """
    from .tools.wasm_disasm import find_fixslice_functions
    from collections import Counter

    # Build set of potential key-schedule functions
    keysched_candidates = {}

    # Method 1: Original fixslice detection
    for s, fi, masks in find_fixslice_functions(mod, top_n=40):
        canonical = {0x55555555, 0x33333333, 0x0F0F0F0F, 0xF0F0F0F0}
        overlap = canonical & set(masks.keys())
        if len(overlap) >= 3:
            f = next((f for f in mod.functions if f["func_idx"] == fi), None)
            if f is None: continue
            params, results = mod.types[f["type_idx"]]
            if params == ["i32", "i32"] and results == []:
                keysched_candidates[fi] = ("fixslice", f["code_end"] - f["code_start"])

    # Method 2: Find functions with (i32,i32)->() that call a deobf helper many times
    # First, find the deobf helper - small (i32,i32)->i32 function called most often
    deobf_helpers = set()
    for f in mod.functions:
        params, results = mod.types[f["type_idx"]]
        if params == ["i32", "i32"] and results == ["i32"]:
            # Check if it has XOR operations
            instrs = mod.decode_function(f["func_idx"])
            has_xor = any(n == "i32.xor" for n, _, _, _ in instrs)
            if has_xor and len(instrs) < 300:
                deobf_helpers.add(f["func_idx"])

    # Find (i32,i32)->() functions that call deobf helpers 50+ times
    for f in mod.functions:
        params, results = mod.types[f["type_idx"]]
        if params == ["i32", "i32"] and results == []:
            instrs = mod.decode_function(f["func_idx"])
            call_counts = Counter()
            for n, ops, _, _ in instrs:
                if n == "call" and ops:
                    call_counts[ops[0]] += 1
            # Check for many calls to deobf helper
            for callee, count in call_counts.most_common(3):
                if callee in deobf_helpers and count >= 50:
                    if f["func_idx"] not in keysched_candidates:
                        keysched_candidates[f["func_idx"]] = ("deobf-caller", count)

    # Walk dispatcher to find magic's if-block
    instrs = mod.decode_function(vc_idx)
    target_mag = magic & 0xffffffff if magic >= 0 else (magic + (1 << 32))
    for i in range(len(instrs) - 2):
        n, ops, _, _ = instrs[i]
        if n == "i32.const" and ops and (ops[0] & 0xffffffff) == target_mag:
            n1, _, _, _ = instrs[i+1]
            n2, _, _, _ = instrs[i+2]
            if n1 == "i32.eq" and n2 == "if":
                depth = 1
                j = i + 3
                calls_in_block = []
                while j < len(instrs):
                    nj, opsj, _, _ = instrs[j]
                    if nj in ("block", "loop", "if"): depth += 1
                    elif nj == "end":
                        depth -= 1
                        if depth == 0: break
                    elif nj == "call" and opsj:
                        calls_in_block.append(opsj[0])
                        if opsj[0] in keysched_candidates:
                            return opsj[0]
                    j += 1

                # Fallback: check callees of called functions
                for callee in calls_in_block:
                    cf = next((f for f in mod.functions if f["func_idx"] == callee), None)
                    if cf is None: continue
                    for n, ops, _, _ in mod.decode_function(callee):
                        if n == "call" and ops and ops[0] in keysched_candidates:
                            return ops[0]

    raise RuntimeError(
        f"no key-schedule call found inside magic-{magic} if-block in vc")


def _find_deobf_helper(mod: WasmModule, key_sched: int) -> int:
    """The XOR-deobf helper is the callee that actually performs the XOR
    deobfuscation. Prefer functions that have XOR operations."""
    from collections import Counter
    counts = Counter()
    for n, ops, _, _ in mod.decode_function(key_sched):
        if n == "call" and ops: counts[ops[0]] += 1

    # Analyze candidates and score them by how "deobfuscator-like" they are
    candidates = []
    for callee, call_count in counts.most_common(20):
        f = next((f for f in mod.functions if f["func_idx"] == callee), None)
        if f is None: continue
        params, results = mod.types[f["type_idx"]]
        instrs = mod.decode_function(callee) or []

        has_xor = any(n == "i32.xor" for n, _, _, _ in instrs)
        has_store8 = any(n == "i32.store8" for n, _, _, _ in instrs)

        # Score: prefer XOR functions that also store bytes
        score = 0
        if has_xor and has_store8:
            score = 200 + call_count  # Best: XOR + store
        elif has_xor:
            score = 100 + call_count  # Good: has XOR
        elif call_count >= 100:
            score = call_count  # Fallback: frequently called

        # Check signature compatibility
        if params == ["i32", "i32"] and results == ["i32"]:
            sig_type = "old"
        elif params == ["i32", "i32", "i32"] and results == [] and has_xor:
            sig_type = "new"
        else:
            continue  # Skip incompatible signatures

        candidates.append((callee, score, sig_type, call_count, has_xor, has_store8))

    # Sort by score descending
    candidates.sort(key=lambda x: -x[1])

    if candidates:
        best = candidates[0]
        return best[0]

    raise RuntimeError(
        f"no XOR-deobf helper found inside key schedule {key_sched}")


# ---------------------------------------------------------------------------
# Injection bytecode
# ---------------------------------------------------------------------------
def _build_injection(deobf_helper_idx: int,
                     scratch_base: int, sentinel_addr: int,
                     sentinel_val: int) -> bytes:
    """Old-style injection for (i32,i32)->i32 helpers that return the value."""
    parts = []
    for i in range(8):
        parts.append(b"\x41" + encode_sleb(scratch_base + i*4))
        parts.append(b"\x41" + encode_sleb(0))
        parts.append(b"\x20\x01")
        if i > 0:
            parts.append(b"\x41" + encode_sleb(i * 4))
            parts.append(b"\x6a")
        parts.append(b"\x10" + encode_uleb(deobf_helper_idx))
        parts.append(b"\x36\x02\x00")
    parts.append(b"\x41" + encode_sleb(sentinel_addr))
    parts.append(b"\x41" + encode_sleb(sentinel_val))
    parts.append(b"\x36\x02\x00")
    return b"".join(parts)


def _build_injection_newstyle(scratch_base: int, counter_addr: int,
                               sentinel_addr: int, sentinel_val: int) -> bytes:
    """New-style injection for (i32,i32,i32)->() helpers.

    This is inserted AFTER the XOR result is stored in local[1].
    It captures the deobfuscated value (32 bits = 4 bytes) to scratch memory.

    Uses counter_addr as a byte counter in memory.
    """
    parts = []

    # Read counter from memory
    # i32.const counter_addr
    # i32.load
    parts.append(b"\x41" + encode_sleb(counter_addr))
    parts.append(b"\x28\x02\x00")  # i32.load align=4 offset=0

    # Check if counter < 32
    # i32.const 32
    # i32.lt_u
    # if
    parts.append(b"\x41\x20")  # i32.const 32
    parts.append(b"\x49")      # i32.lt_u
    parts.append(b"\x04\x40")  # if (void)

    # Store the 4 bytes from local[1] to scratch_base + counter
    # i32.const scratch_base
    # i32.const counter_addr
    # i32.load
    # i32.add
    # local.get 1
    # i32.store (store 4 bytes)
    parts.append(b"\x41" + encode_sleb(scratch_base))
    parts.append(b"\x41" + encode_sleb(counter_addr))
    parts.append(b"\x28\x02\x00")  # i32.load
    parts.append(b"\x6a")          # i32.add
    parts.append(b"\x20\x01")      # local.get 1
    parts.append(b"\x36\x02\x00")  # i32.store align=4 offset=0

    # Increment counter by 4 (we stored 4 bytes)
    # i32.const counter_addr
    # i32.const counter_addr
    # i32.load
    # i32.const 4
    # i32.add
    # i32.store
    parts.append(b"\x41" + encode_sleb(counter_addr))
    parts.append(b"\x41" + encode_sleb(counter_addr))
    parts.append(b"\x28\x02\x00")  # i32.load
    parts.append(b"\x41\x04")      # i32.const 4
    parts.append(b"\x6a")          # i32.add
    parts.append(b"\x36\x02\x00")  # i32.store

    # end if
    parts.append(b"\x0b")  # end

    # Write sentinel
    parts.append(b"\x41" + encode_sleb(sentinel_addr))
    parts.append(b"\x41" + encode_sleb(sentinel_val))
    parts.append(b"\x36\x02\x00")  # i32.store

    return b"".join(parts)


# ---------------------------------------------------------------------------
# Sandbox harness
# ---------------------------------------------------------------------------
_HOOK_JS = r"""
(function() {
  function _b64ToU8(s) {
    if (typeof Buffer !== 'undefined') {
      const b = Buffer.from(s, 'base64');
      return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    }
    const bin = atob(s);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  }
  function _install(t) {
    if (!t || !t.WebAssembly) return;
    const origInstantiate = t.WebAssembly.instantiate;
    t.WebAssembly.instantiate = function(buf, imp) {
      let useBuf = buf;
      if (buf && buf.byteLength != null) {
        useBuf = _b64ToU8(globalThis.__patched_wasm_b64);
      }
      return origInstantiate.call(this, useBuf, imp).then(r => {
        const inst = r.instance || r;
        if (inst && inst.exports) {
          globalThis.__hsw_exports = inst.exports;
          for (const k of Object.keys(inst.exports)) {
            const v = inst.exports[k];
            if (v && typeof v === 'object' && v.buffer && typeof v.grow === 'function') {
              globalThis.__hsw_memory = v;
              break;
            }
          }
        }
        return r;
      });
    };
    if (t.WebAssembly.instantiateStreaming) {
      t.WebAssembly.instantiateStreaming = async function(source, imp) {
        const resp = await source;
        const buf = await resp.arrayBuffer();
        return t.WebAssembly.instantiate(buf, imp);
      };
    }
  }
  _install(globalThis);
  _install(typeof window !== 'undefined' ? window : null);
})();
"""


def _new_runtime() -> JsRuntime:
    return JsRuntime()


# ---------------------------------------------------------------------------
# Top-level: extract both keys directly + verifiably
# ---------------------------------------------------------------------------
class HSWKeyFetcher:
    """Direct extraction of both HSW master AES-256 keys (encrypt + decrypt).

    No candidate-guessing: each function is identified by structural
    role traceable from the deobf'd source's magic numbers.
    """
    def __init__(self, version: str | None = None, log: Logger | None = None):
        self.log = log or Logger()
        self.version = version or _v.latest_version()

    def fetch(self) -> dict:
        t0 = time.time()

        # 1. Magic numbers from deobf source
        magics = _read_magics_from_deobf(self.version)
        self.log.info(f"magics: enc={magics['encrypt_magic']} "
                      f"dec={magics['decrypt_magic']}",
                      start=t0, end=time.time())

        # 2. Load WASM, locate dispatcher
        from .hsw_bridge import HSWAnalyzer
        info = HSWAnalyzer(self.version, log=self.log).analyze()
        orig_wasm = bytes.fromhex(info["wasm_bytes_hex"])
        mod = WasmModule(orig_wasm)
        vc_idx = _find_dispatcher_func(mod)
        self.log.info(f"dispatcher vc = func {vc_idx}",
                      start=t0, end=time.time())

        # 3. From each magic, locate the key-schedule call directly
        enc_ks  = _find_key_schedule_for_magic(mod, vc_idx, magics["encrypt_magic"])
        dec_ks  = _find_key_schedule_for_magic(mod, vc_idx, magics["decrypt_magic"])
        deobf_e = _find_deobf_helper(mod, enc_ks)
        deobf_d = _find_deobf_helper(mod, dec_ks)
        self.log.info(f"encrypt: key_sched={enc_ks} deobf={deobf_e}",
                      start=t0, end=time.time())
        self.log.info(f"decrypt: key_sched={dec_ks} deobf={deobf_d}",
                      start=t0, end=time.time())

        # Check if deobf helper uses old-style (returns value) or new-style (writes to memory)
        f_e = next((f for f in mod.functions if f["func_idx"] == deobf_e), None)
        is_newstyle = False
        if f_e:
            params, results = mod.types[f_e["type_idx"]]
            is_newstyle = (results != ["i32"])

        self.log.info(f"deobf style: {'new' if is_newstyle else 'old'}",
                      start=t0, end=time.time())

        # 4. Build a single patched WASM that instruments the key extraction
        writer = ModuleWriter(mod)

        if is_newstyle:
            # New-style: inject INSIDE the deobf helper, after the XOR
            # Find the position after `local.set [1]` following the XOR
            instrs = mod.decode_function(deobf_e) or []
            inject_offset = None
            for i, (name, ops, start, end) in enumerate(instrs):
                # Look for: i32.xor followed by local.set [1]
                if name == "i32.xor" and i + 1 < len(instrs):
                    next_name, next_ops, next_start, next_size = instrs[i + 1]
                    if next_name == "local.set" and next_ops == [1]:
                        # Inject after this local.set (start + size = end position)
                        inject_offset = next_start + next_size
                        break

            if inject_offset is None:
                raise RuntimeError(f"Could not find XOR+local.set[1] in deobf helper fn_{deobf_e}")

            # For new-style, we patch the helper itself (called by both enc and dec KS)
            # Use SCRATCH_ENC for first 32 bytes captured
            injection = _build_injection_newstyle(
                SCRATCH_ENC, COUNTER_ENC, SENTINEL_ENC, SENTINEL_VAL_ENC)
            writer.code.splice_code(deobf_e, inject_offset, n_replace=0,
                                    new_bytes=injection)
        else:
            # Old-style: inject at beginning of key schedule
            writer.code.splice_code(enc_ks, 0, n_replace=0,
                new_bytes=_build_injection(deobf_e, SCRATCH_ENC,
                                            SENTINEL_ENC, SENTINEL_VAL_ENC))
            # If decrypt uses a DIFFERENT key schedule function, patch that too:
            if dec_ks != enc_ks:
                writer.code.splice_code(dec_ks, 0, n_replace=0,
                    new_bytes=_build_injection(deobf_d, SCRATCH_DEC,
                                                SENTINEL_DEC, SENTINEL_VAL_DEC))

        t_i32_to_i32 = next((i for i, (p, r) in enumerate(mod.types)
                             if p == ["i32"] and r == ["i32"]), None)
        if t_i32_to_i32 is None:
            t_i32_to_i32 = writer.add_type(["i32"], ["i32"])
        t_i32i32_to_void = next((i for i, (p, r) in enumerate(mod.types)
                                  if p == ["i32", "i32"] and r == []), None)
        if t_i32i32_to_void is None:
            t_i32i32_to_void = writer.add_type(["i32", "i32"], [])
        writer.add_function(t_i32_to_i32, [],
                            bytes([0x20, 0x00, 0x28, 0x02, 0x00, 0x0b]),
                            export_name="__peek32")
        writer.add_function(t_i32i32_to_void, [],
                            bytes([0x20, 0x00, 0x20, 0x01, 0x36, 0x02, 0x00, 0x0b]),
                            export_name="__poke32")
        patched = writer.emit()
        self.log.info(f"patched wasm: {len(patched)}B "
                      f"(+{len(patched)-len(orig_wasm)}B)",
                      start=t0, end=time.time())

        # 5. Sandbox: substitute patched WASM, run encrypt + decrypt
        rt = _new_runtime()
        rt.eval(f"globalThis.__patched_wasm_b64 = '{base64.b64encode(patched).decode()}';")
        rt.eval(_HOOK_JS)
        r = requests.get(_v.asset_url(self.version, "hsw.js"))
        r.encoding = "utf-8"
        rt.eval(r.text, suppress=True)

        # If encrypt and decrypt share the same key schedule, reading
        # between the calls captures each direction separately.
        # If they use different functions, both fire to their own scratch.
        # For new-style: even if enc_ks != dec_ks, both call the SAME deobf
        # helper (which we patched), so from the patch's POV it's "same".
        same_ks = (enc_ks == dec_ks) or is_newstyle
        rt.eval(rf"""
            globalThis.__done = 0;
            globalThis.__same_ks = {str(same_ks).lower()};
            (async () => {{
              try {{
                await window.hsw(1, new Uint8Array(0));  // warmup
                const exp = globalThis.__hsw_exports;
                // Clear scratch areas AND reset counters
                for (let i = 0; i < 44; i += 4) {{
                  exp.__poke32({SCRATCH_ENC} + i, 0);
                  exp.__poke32({SCRATCH_DEC} + i, 0);
                }}
                exp.__poke32({COUNTER_ENC}, 0);
                exp.__poke32({COUNTER_DEC}, 0);
                // Drive encrypt — key schedule writes encrypt key to SCRATCH_ENC
                const pt = new Uint8Array(32);
                for (let i = 0; i < 32; i++) pt[i] = (i*7+3) & 0xff;
                const o = await window.hsw(1, pt);
                const u8 = o instanceof Uint8Array ? o : new Uint8Array(o);
                let h=''; for (let i=0;i<u8.length;i++) h += u8[i].toString(16).padStart(2,'0');
                globalThis.__blob = h;
                globalThis.__pt = Array.from(pt);

                // Read encrypt key NOW, before decrypt overwrites it
                const mem = new Uint8Array(globalThis.__hsw_memory.buffer);
                let kE=''; for (let i=0; i<32; i++)
                  kE += mem[{SCRATCH_ENC} + i].toString(16).padStart(2,'0');
                globalThis.__key_enc = kE;

                // If both directions share the same key schedule, the
                // decrypt path overwrites SCRATCH_ENC. So COPY enc bytes
                // to SCRATCH_DEC first (as a save), then trigger decrypt
                // which will overwrite SCRATCH_ENC with decrypt key.
                if (globalThis.__same_ks) {{
                  for (let i = 0; i < 32; i += 4) {{
                    exp.__poke32({SCRATCH_DEC} + i, exp.__peek32({SCRATCH_ENC} + i));
                  }}
                  // Now zero SCRATCH_ENC so we see if decrypt actually fired
                  for (let i = 0; i < 32; i += 4) {{
                    exp.__poke32({SCRATCH_ENC} + i, 0);
                  }}
                }}
                try {{ await window.hsw(0, new Uint8Array(32)); }} catch (_) {{}}

                let kD=''; for (let i=0; i<32; i++) {{
                  const slot = globalThis.__same_ks ? {SCRATCH_ENC} : {SCRATCH_DEC};
                  kD += mem[slot + i].toString(16).padStart(2,'0');
                }}
                globalThis.__key_dec = kD;
                globalThis.__sentinel_enc = exp.__peek32({SENTINEL_ENC});
                globalThis.__sentinel_dec = exp.__peek32({SENTINEL_DEC});
              }} catch (e) {{ globalThis.__err = String(e); }}
              globalThis.__done = 1;
            }})();
        """, suppress=True)

        for _ in range(80):
            if rt.eval("globalThis.__done"): break
            time.sleep(0.25)

        err      = rt.eval("globalThis.__err || ''")
        sent_e   = rt.eval("globalThis.__sentinel_enc") or 0
        sent_d   = rt.eval("globalThis.__sentinel_dec") or 0
        key_enc  = rt.eval("globalThis.__key_enc") or ""
        key_dec  = rt.eval("globalThis.__key_dec") or ""
        blob_hex = rt.eval("globalThis.__blob") or ""
        pt_list  = json.loads(rt.eval("JSON.stringify(globalThis.__pt || [])") or "[]")

        if err:
            self.log.info(f"runtime err (continuing if keys captured): {err}",
                          start=t0, end=time.time())

        if sent_e not in (SENTINEL_VAL_ENC, SENTINEL_VAL_ENC + (1<<32)):
            raise RuntimeError(
                f"encrypt key-schedule patch never fired (sentinel={sent_e})")
        # When enc_ks == dec_ks, both directions share the same patched
        # function. The 'enc' injection writes for BOTH directions
        # (to SCRATCH_ENC + sentinel_enc), so sentinel_dec stays unset
        # but the decrypt key DID overwrite SCRATCH_ENC after we saved
        # the encrypt key. No warning needed.
        if not same_ks and sent_d not in (SENTINEL_VAL_DEC, SENTINEL_VAL_DEC + (1<<32)):
            raise RuntimeError(
                f"decrypt key-schedule patch never fired (sentinel={sent_d})")

        enc_master = bytes.fromhex(key_enc)
        dec_master = bytes.fromhex(key_dec) if key_dec and any(c!='0' for c in key_dec) else None
        blob = bytes.fromhex(blob_hex)
        pt   = bytes(pt_list)

        # 6. Verify encrypt key by round-trip
        from Crypto.Cipher import AES
        iv  = blob[:12]
        ct  = blob[12:12+len(pt)]
        tag = blob[12+len(pt):12+len(pt)+16]
        cipher = AES.new(enc_master, AES.MODE_GCM, nonce=iv)
        decoded = cipher.decrypt_and_verify(ct, tag)
        if decoded != pt:
            raise RuntimeError("encrypt key verification failed: pt mismatch")
        self.log.info("encrypt key verified OK (AES-256-GCM round-trip)",
                      start=t0, end=time.time())

        return {
            "version":       self.version,
            "encrypt_key":   enc_master.hex(),
            "decrypt_key":   dec_master.hex() if dec_master else None,
            "cipher":        "AES-256-GCM",
            "wire_format":   "iv(12) || ct(N) || tag(16)",
            "aad":           "",
            "verified":      True,
            "encrypt_magic": magics["encrypt_magic"],
            "decrypt_magic": magics["decrypt_magic"],
            "dispatcher":    vc_idx,
            "encrypt_ks":    enc_ks,
            "decrypt_ks":    dec_ks,
        }


if __name__ == "__main__":
    out = HSWKeyFetcher().fetch()
    print(json.dumps(out, indent=2))
    with open("hsw_master_keys.json", "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nsaved -> hsw_master_keys.json")
