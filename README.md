# hcaptcha-keys

[![Update keys](https://github.com/opastorello/hcaptcha-keys/actions/workflows/update-keys.yml/badge.svg)](https://github.com/opastorello/hcaptcha-keys/actions/workflows/update-keys.yml)
![updates hourly](https://img.shields.io/badge/updates-hourly-brightgreen)
![last commit](https://img.shields.io/github/last-commit/opastorello/hcaptcha-keys)
![cipher](https://img.shields.io/badge/cipher-AES--256--GCM-blue)
![license](https://img.shields.io/github/license/opastorello/hcaptcha-keys)

> **Auto-updating hCaptcha AES-256 keys** — extracted and verified **independently**
> from hCaptcha's own bundle, every hour. No third-party key feed.

The current build's `request_key` / `response_key` live in
**[`data/keys.json`](data/keys.json)**; every build ever seen is archived under
**[`data/history/`](data/history/)**.

- 🔑 **Both bundles** — `hsw` always; `hsj` (fingerprint) when it shares the same keys (`matches_hsw`)
- ✅ **Verified** — every key is proven against the bundle's own AES before it ships (nothing guessed)
- 🔁 **Build-robust** — keys rotate several times a day; structural detection follows automatically, no hard-coded indices
- 🧩 **Pure crypto** — use the keys in plain AES-256-GCM, no WASM/JS runtime in the loop
- 🔬 **Documented** — a full [`research/`](research/SUMMARY.md) set on the protocol & defense design

```bash
# grab the latest keys
curl -s https://raw.githubusercontent.com/opastorello/hcaptcha-keys/main/data/keys.json
```

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
  },
  "hsj": {                               // present when hsj shares the hsw keys
    "cipher": "AES-256-GCM",
    "request_key":  "<64 hex>",          // == hsw.request_key
    "response_key": "<64 hex>",          // == hsw.response_key
    "request_wire": "iv(12) || ct(N) || tag(16)",
    "response_wire": "iv(12) || ct(N) || tag(16)",
    "verified": true,
    "matches_hsw": true,
    "extraction_method": "hsj oracle key-equivalence (shares hsw keys)",
    "extracted_at": "<iso8601>"
  }
}
```

- `request_key` — `encrypt_req_data` (`window.hsw(1, …)`).
- `response_key` — `decrypt_resp_data` (`window.hsw(0, …)`).
- Keys are build-static and rotate with the asset build (several times a day).
- **`hsj`** (the fingerprint / `inspekt_client` bundle) is included when it is
  verified — against hsj's own oracle — to use the *same* AES keys as hsw
  (`matches_hsw`). On builds where hsj uses independent keys the block is omitted
  rather than published unverified.

## Verification

Every published key is checked against the build's own bundle before it ships —
nothing is guessed:

- **request_key**: GCM-decrypting the bundle's own `hsw(1, pt)` output under
  the key returns `pt`.
- **response_key**: `hsw(0, iv || GCM(key, iv, pt) || tag)` returns `pt`.
- Both masters are also **self-verified**: the recovered 32-byte key must
  regenerate the full 120-word fixslice AES-256 schedule captured live
  (120/120 word match).
- **hsj**: verified by key-equivalence against hsj's own `hsj(1)` / `hsj(0)`.

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

- **[`research/SUMMARY.md`](research/SUMMARY.md) — start here: executive summary + findings**
- [`research/protocol.md`](research/protocol.md) — client protocol & crypto whitepaper
- [`research/crypto-analysis.md`](research/crypto-analysis.md) — encryption/decryption construction analysis (AEAD, IV, keys, n-token)
- [`research/hcaptcha-defense.md`](research/hcaptcha-defense.md) — visual challenge taxonomy + layered defense
- [`research/motiondata-signal.md`](research/motiondata-signal.md) — behavioral signal analysis (detection view)
- [`research/pow-hsw.md`](research/pow-hsw.md) — hsw proof-of-work cost analysis (Hashcash/SHA-1)
- [`research/captcha-comparison.md`](research/captcha-comparison.md) — hCaptcha vs Turnstile vs reCAPTCHA v3
- [`research/turnstile-architecture.md`](research/turnstile-architecture.md) — Turnstile architecture deep-dive
- [`research/recaptcha-enterprise.md`](research/recaptcha-enterprise.md) — reCAPTCHA Enterprise signal-level analysis
- [`research/recaptcha-v3-why-opaque.md`](research/recaptcha-v3-why-opaque.md) — why v3 resists client-side extraction
- [`research/related-work.md`](research/related-work.md) — the hCaptcha RE/solver ecosystem (by layer + activity)
- [`research/measurement-design.md`](research/measurement-design.md) — responsible study methodology

## Disclaimer

For security research and interoperability testing. Uses only hCaptcha's own
publicly-served bundle. No affiliation with hCaptcha / Intuition Machines.
This repository characterizes the transport/crypto layer and defense *design*;
it contains **no challenge solver, no behavioral-signal synthesis, and no bypass**.
