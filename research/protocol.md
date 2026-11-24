# hCaptcha client protocol — technical whitepaper (research notes)

Descriptive documentation of hCaptcha's client-side challenge/response protocol
as observed through protocol reverse engineering of the public demo sitekey.
Transport/crypto layer only — no evasion content.

---

## 1. Assets and versioning

A page embedding hCaptcha loads, from `newassets.hcaptcha.com/c/<version>/`:

| Asset | Role |
|-------|------|
| `hcaptcha.js` | visible UI loader / widget bootstrap |
| `hsj.js` | `inspekt_client` — asm.js fingerprint collector + n-token path (textbook AES, keys live in a JS heap) |
| `hsw.js` | wasm-bindgen Rust module — proof-of-work + request/response AEAD (RustCrypto `fixslice32` AES) |

`<version>` is a 64-hex build hash that **rotates frequently** (observed every
few minutes to a few hours). The current hash is served inside a JWT from
`hcaptcha.com/checksiteconfig`. Function indices, dispatch magics, and the AES
master keys all rotate with the build.

## 2. Handshake

```
POST /checksiteconfig?v=<version>&host=<host>&sitekey=<key>&...
 └▶ { features:{ enc_get_req, andint, ... }, c:{ type:"hsw", req:<JWT> }, pass }
```

- `features.enc_get_req = true` → the `getcaptcha` request body is itself
  AES-encrypted (not just TLS).
- `c.req` is the first **hsw proof-of-work** challenge (a JWT the client must
  "solve" via `window.hsw(req)`).

## 3. Crypto layer

- **Cipher:** AES-256-GCM, empty AAD.
- **Wire format:** `iv(12) || ciphertext(N) || tag(16)`.
- **Two build-static keys:**
  - `request_key` → `encrypt_req_data` (`window.hsw(1, bytes)`) — client → server.
  - `response_key` → `decrypt_resp_data` (`window.hsw(0, blob)`) — server → client.
  - They are a matched pair **with the server**, not with each other, and are
    constant for a given build (they rotate when `<version>` rotates).
- **n-token cipher** (the PoW/fingerprint blob): AES-256-CTR, counter block
  `iv || be32(counter)` (distinct from the GCM request/response path).

**Key storage.** In `hsw.js` the AES schedule uses RustCrypto `fixslice32`; the
round keys never sit in linear memory as 32 contiguous plaintext bytes (they are
deobfuscated on-demand through a paged XOR reader). The master is nonetheless
recoverable by instrumenting the schedule and inverting it — i.e. the crypto is
*transport confidentiality*, not an anti-bot control (see
[`hcaptcha-defense.md`](./hcaptcha-defense.md) §1).

## 4. getcaptcha request (client → server)

Body is msgpack (binary, `application/octet-stream`):

```
[ "<hsw-token JSON>",            # element 0: {"type":"hsw","req":"<JWT>"} — PoW result
  Ext(18, <AES-256-GCM blob>) ]  # element 1: encrypted client telemetry
```

The decrypted telemetry map (schema, observed):

| Field | Meaning |
|-------|---------|
| `v`, `sitekey`, `host`, `hl` | build + widget identity |
| `motionData` | pointer trajectory, timestamps, screen geometry, orientation |
| `pdc`, `pem` | perf/timing counters |
| `n` | proof/fingerprint blob (base64) |
| `ws`, `clientOptions`, `psd` | widget stats, config, seed |

(Listed as *schema*; this document does not describe how to synthesize values.)

## 5. getcaptcha response (server → client)

AES-256-GCM under `response_key`; plaintext is a msgpack challenge map:

| Field | Meaning |
|-------|---------|
| `request_type` | challenge family (`image_label_*`) |
| `requester_question` | localized prompt |
| `request_config` | shape/answer constraints |
| `tasklist[]` | `datapoint_uri` images + `task_key` |
| `key`, `oby` | submission + grading tokens |
| `c` | the **next** chained hsw PoW challenge |

## 6. Proof-of-work (hsw)

- `window.hsw(jwt)` consumes `c.req` and emits an n-token.
- Algorithm: **Hashcash v1 + SHA-1** (`rust-hashcash` style), parameters encoded
  in the JWT (`d` difficulty, `s`, `t`, etc.).
- Purpose: impose *computational cost* per request (economic rate-limiting), not
  bot detection per se.

## 7. Submission

`checkcaptcha` (POST) returns the pass token after the server grades the
answers **together with** behavior + reputation (see the defense doc). The
response also chains the next `c` challenge, so sessions are stateful.

## 8. Build-rotation implications (for tooling that studies the protocol)

Because indices/magics/keys rotate per build, any analysis must key off
**structural fingerprints** (page-size arithmetic, fixslice masks, call-graph
roles), never hard-coded indices. The `data/keys.json` + `data/history/` in this
repo are produced exactly that way and are the machine-readable record of the
crypto layer across builds.
