# hcaptcha-keys

Auto-updating hCaptcha **hsw** AES-256 keys, one build at a time.

A GitHub Actions job runs **every hour**, detects the current hCaptcha asset
build, and — when the build rotates — extracts and verifies both AES-256 keys
**locally, from hCaptcha's own bundle**, with no third-party key feed. Results
are written to [`data/keys.json`](data/keys.json) (current build) and archived
per build under [`data/history/`](data/history/).

## Schema

`data/keys.json`:

```json
{
  "version": "<asset build hash>",
  "last_checked": "<iso8601>",
  "last_updated": "<iso8601>",
  "hsw": {
    "cipher": "AES-256-GCM",
    "request_key":  "<64 hex>",
    "request_wire": "iv(12) || ct(N) || tag(16)",
    "response_key": "<64 hex>",
    "response_wire": "iv(12) || ct(N) || tag(16)",
    "verified": true,
    "extraction_method": "fixslice bitslice write interception + module oracle",
    "wasm_sha256": "...",
    "bundle_sha256": "...",
    "functions": { "u32_writer": 0, "fixslice_functions": [] },
    "extracted_at": "<iso8601>"
  }
}
```

- `request_key` — `encrypt_req_data` (`window.hsw(1, …)`).
- `response_key` — `decrypt_resp_data` (`window.hsw(0, …)`).
- Keys are build-static and rotate with the asset build (several times a day).

## Verification

Every published key is checked against the build's own WASM before it ships —
nothing is guessed:

- **request_key**: GCM-decrypting the bundle's own `hsw(1, pt)` output under
  the key returns `pt`.
- **response_key**: `hsw(0, iv || GCM(key, iv, pt) || tag)` returns `pt`.
- Both masters are also **self-verified**: the recovered 32-byte key must
  regenerate the full 120-word fixslice AES-256 schedule captured live
  (120/120 word match).

## How extraction works

The bundle's AES is RustCrypto `fixslice32`. The round-key schedule never
appears as 32 contiguous bytes in memory (it is deobfuscated on-demand per
4-byte read). But it is *written* to that store through virtual-memory writer
functions `writer(base, value, offset)` where `value` is the **plaintext**
word. We splice a capture prologue into the `u32` writer, record the schedule
as it is written during a gated `hsw(1)` / `hsw(0)` call, reassemble it in the
clear, and invert it to the master key — then verify as above.

Everything is located by **structural fingerprint**, never by hard-coded
function index, so it survives the frequent build rotations automatically.

See [`STATUS.md`](STATUS.md) and `src/hcaptcha/hsw_keys_local.py`.

## Use the keys (pure Python, no WASM)

```python
import json, os
from Crypto.Cipher import AES

k = json.load(open("data/keys.json"))["hsw"]
req = bytes.fromhex(k["request_key"])

def hsw_encrypt(pt, key):          # iv(12) || ct || tag(16)
    iv = os.urandom(12)
    ct, tag = AES.new(key, AES.MODE_GCM, nonce=iv).encrypt_and_digest(pt)
    return iv + ct + tag

def hsw_decrypt(blob, key):
    iv, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    return AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(ct, tag)
```

## Run it yourself

```bash
pip install pycryptodome xxhash msgpack jsbeautifier requests
npm ci                      # jsdom + canvas (Node 18+)
python tools/update_keys.py --data-dir data
```

## Research notes

Descriptive, defensive/educational analysis of hCaptcha's protocol and defense
design (no solver / no bypass):

- **[`RESEARCH-SUMMARY.md`](RESEARCH-SUMMARY.md) — start here: executive summary + findings**
- [`RESEARCH-protocol.md`](RESEARCH-protocol.md) — client protocol & crypto whitepaper
- [`RESEARCH-hcaptcha-defense.md`](RESEARCH-hcaptcha-defense.md) — visual challenge taxonomy + layered defense
- [`RESEARCH-motiondata-signal.md`](RESEARCH-motiondata-signal.md) — behavioral signal analysis (detection view)
- [`RESEARCH-pow-hsw.md`](RESEARCH-pow-hsw.md) — hsw proof-of-work cost analysis (Hashcash/SHA-1)
- [`RESEARCH-captcha-comparison.md`](RESEARCH-captcha-comparison.md) — hCaptcha vs Turnstile vs reCAPTCHA v3
- [`RESEARCH-turnstile-architecture.md`](RESEARCH-turnstile-architecture.md) — Turnstile architecture deep-dive
- [`RESEARCH-recaptcha-enterprise.md`](RESEARCH-recaptcha-enterprise.md) — reCAPTCHA Enterprise signal-level analysis
- [`RESEARCH-recaptcha-v3-why-opaque.md`](RESEARCH-recaptcha-v3-why-opaque.md) — why v3 resists client-side extraction
- [`RESEARCH-measurement-design.md`](RESEARCH-measurement-design.md) — responsible study methodology

## Disclaimer

For security research and interoperability testing. Uses only hCaptcha's own
publicly-served bundle. No affiliation with hCaptcha / Intuition Machines.
This repository characterizes the transport/crypto layer and defense *design*;
it contains no challenge solver, no behavioral-signal synthesis, and no bypass.
