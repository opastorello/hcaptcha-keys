# hCaptcha Keys Local - Status

## Current State

The project does **independent encrypt AND decrypt** for the current hCaptcha
build using **only hCaptcha's own freely-downloaded bundle**. There is **no
dependency on any third-party key feed** — vastien and CircuitSavage have been
removed entirely. The only network traffic is fetching the bundle from the
hCaptcha asset server.

```python
from hcaptcha.keys_provider import KeysProvider

provider = KeysProvider()           # auto-detects the current build
blob = provider.encrypt(payload)    # request encrypt  (local)
pt   = provider.decrypt(server_blob)# response decrypt (local)
token = provider.solve(req_jwt)     # proof-of-work    (local)
```

## Two local layers (no third parties)

| Layer | What it is | When it is used |
|-------|-----------|-----------------|
| 1. Self-verifying key extraction | `hsw_keys_local.extract_masters_local` recovers the AES-256 master straight from the live bundle and **proves it correct** by rebuilding the full 120-word fixslice schedule (120/120 match). | Whenever a build exposes an invertible schedule. Lets us do the AEAD crypto in pure Python with no WASM in the loop. |
| 2. Local WASM oracle | `HSWBridge` runs the same local bundle and calls its native `encrypt_req_data` (`hsw(1)`) and `decrypt_resp_data` (`hsw(0)`). | Always available; used whenever a verified raw key for that direction is not available. |

Both layers are 100% independent — neither contacts a third party.

## Independence vs. raw-key extraction — the honest picture

- **Independence from vastien / CircuitSavage: DONE.** Both directions run on
  hCaptcha's own local code. No external key feed is consulted.
- **Decrypt validated end-to-end against a REAL server response (2026-11-23,
  build `840714c6…`).** A genuine `getcaptcha` response (2480 bytes,
  `application/octet-stream`, sha256 `256ca802…`) was captured from a live
  hCaptcha session (camoufox) and decrypted by a **fresh, standalone**
  `HSWBridge.decrypt()` into valid msgpack challenge data
  (`request_type: image_label_area_select`, `requester_question`, `tasklist`,
  `key`, `oby`, `c`…). The response key is therefore **build-static** (a fresh
  bridge with no session state decrypted it) — so both encrypt and decrypt are
  confirmed fully local and independent. See `test_decrypt_real.py`.
- **Raw 32-byte key extraction: blocked on current builds (by design).** The
  master key never materialises as 32 contiguous bytes anywhere in observable
  memory. It exists only in deobfuscated-on-demand *paged* form: every 4-byte
  read goes through a reader (`fn_489` on the `840714c6…` build) that does a
  320-byte page lookup (`fn_885`) and XORs with a per-address mask (`fn_881`).
  This is hCaptcha's deliberate anti-RE design.

### Verified this session (build `840714c6d66aa4aa…`, 2026-11-23)

- `fixslice.py` (RustCrypto fixslice32 port) passes its known-answer test
  against pycryptodome AES-256-ECB. The self-verifying inversion in
  `hsw_keys_local` / `hsw_n_token_decrypt.recover_ntoken_master_live` is
  cryptographically sound: `M[:16] = inv_bitslice(rk0)`, and `M[16:]` from
  `rk1` after undoing `sub_bytes_nots` + `shift_rows_1`, then a full
  120/120-word schedule re-derivation gate (never fabricates a key).
- `_find_fixslice_ks_funcs` finds candidates `[372, 919]`; `_find_encrypt_entry`
  returned `None` because the encrypt-entry signature rotated — so the recovery
  was generalised to try **every** candidate x both argument pointers, gated
  only by the self-verification (now in `hsw_keys_local.extract_masters_local`).
- Captured streams on this build:
  - `fn_919` arg0 yields 120 high-entropy deobfuscated words, but they are **not**
    a fixslice schedule (structure mismatch; 4/120 schedule match) and **not** a
    standard AES-256/128 key schedule (0/… recurrence match).
  - Wrapping `fn_489` and mining every (addr,value) read during `hsw(1)` against a
    real oracle ciphertext (AES-256/128, GCM + CTR start 0/1/2, both endiannesses)
    found **no** key — the round keys do not flow through that reader as
    contiguous key material on the encrypt path.
  - Raw linear-memory reads at the schedule pointers are all-zero; only the paged
    reader returns data. Consistent with the project's earlier exhaustive
    full-memory scans (0 matches).

Conclusion: on this build class the raw key is not recoverable by memory
observation, so layer 1 returns `[]` and the provider uses layer 2 (the local
oracle). `extract_masters_local` will light up automatically on any build that
does expose an invertible schedule — no code change needed.

## Wire format

- Request encrypt (`hsw(1)`) output observed this build: `ct(N) || tag(16) || iv(12)`
  (60 bytes for a 32-byte input), AES-256-GCM-shaped. Older builds used
  `iv(12) || ct(N) || tag(16)` (see `hsw_crypto`). The provider auto-detects the
  exact layout/cipher when a raw key is confirmed, by matching the bundle's own
  output, so the pure-Python path can never silently diverge.
- `request_key` (encrypt) and `response_key` (decrypt) are **different** keys
  (a matched pair with the server, not with each other), so a locally-encrypted
  request blob does not round-trip through the local decrypt entry — that is
  expected, not a bug.

## Implementation files

- `src/hcaptcha/keys_provider.py`   - main interface (local only; no third parties)
- `src/hcaptcha/hsw_keys_local.py`  - self-verifying local master-key extraction
- `src/hcaptcha/hsw_bridge.py`      - local WASM oracle: encrypt (hsw 1) + decrypt (hsw 0)
- `src/hcaptcha/hsw_crypto.py`      - pure-Python AES-256-GCM encrypt/decrypt
- `src/hcaptcha/hsw_n_token_decrypt.py` - n-token decrypt + round-key recovery
- `src/hcaptcha/tools/fixslice.py`  - faithful RustCrypto fixslice32 port (+ self-test)
- `src/hcaptcha/tools/wasm_disasm.py` / `wasm_writer.py` - WASM parse/patch

## References

- [RustCrypto aes-soft fixslice32](https://github.com/RustCrypto/block-ciphers/blob/master/aes/src/soft/fixslice32.rs)
