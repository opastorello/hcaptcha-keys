# hCaptcha cryptography — construction analysis (research notes)

A focused cryptographic analysis of how hCaptcha encrypts/decrypts its traffic:
the AEAD construction, nonce handling, key management, the distinct n-token
cipher, and the security properties (and limits) of the design. Descriptive and
defensive; verified against the project's own crypto implementations and live
decrypts.

---

## 1. Encryption surfaces (what is / isn't encrypted)

| Surface | Encrypted? | Cipher |
|---|---|---|
| `hcaptcha.js` / `hsj.js` / `hsw.js` assets | no (obfuscated JS, not encrypted) | — |
| `checksiteconfig` response | no — plaintext JSON (`features`, `c.req` JWT) | — |
| `getcaptcha` **request** body | yes | AES-256-GCM (inside msgpack `Ext(18)`) |
| `getcaptcha` **response** body | yes | AES-256-GCM |
| `checkcaptcha` (submission) | yes (same scheme) | AES-256-GCM |
| n-token (`window.hsw(jwt)` output) | yes | **AES-256-CTR** (separate construction) |

Key point: the *protocol metadata* (config, build hash, challenge JWT) travels
in the clear; only the request/response **payloads** and the n-token are
encrypted.

## 2. The request/response AEAD

- **Primitive:** AES-256-GCM.
- **Wire format:** `iv(12) ‖ ciphertext(N) ‖ tag(16)`.
- **AAD:** empty.
- **Keys:** two per build — `request_key` (`encrypt_req_data`) and `response_key`
  (`decrypt_resp_data`), each 256-bit, **build-static** (constant for a given
  asset `<version>`, rotated when the build rotates).

### 2.1 Properties this gives

- **Confidentiality + integrity (AEAD).** GCM authenticates the ciphertext: a
  tampered body fails `decrypt_and_verify`. We confirmed this empirically — a
  wrong-key or altered blob is rejected; the correct key reproduces the plaintext
  and the tag verifies.
- **Directionality.** request and response use *different* keys, so a client
  cannot "decrypt its own request" — each key is paired with the **server**.

### 2.2 Nonce (IV) analysis

- 96-bit IV, one per message, random in observed traffic (the reference
  implementation draws `os.urandom(12)` per encrypt).
- **GCM is catastrophic on nonce reuse under the same key** (reused (K, IV)
  leaks the XOR of plaintexts and enables forgery via the authentication
  subkey H). With a *build-static* key and random 96-bit IVs, the birthday bound
  is ~2⁴⁸ messages before a meaningful collision probability — comfortably safe
  for a per-build key's lifetime (builds rotate in minutes–hours). So random-IV
  GCM here is sound **provided** the RNG is a real CSPRNG and IVs never repeat
  within a build. This is the one place a weak client RNG would be a real
  cryptographic bug; nothing in observed traffic suggests one.

### 2.3 Empty-AAD analysis

- With empty AAD, the ciphertext is **not cryptographically bound** to session,
  URL, sitekey, or timestamp. GCM still guarantees the blob wasn't tampered, but
  the crypto layer alone does not stop a blob from being lifted and replayed into
  a *different* context — any such binding is enforced at the **application**
  layer (session nonces, the chained `c` challenge, server state), not by the
  cipher. A defensive design would feed context (sitekey/host/expiry) as AAD;
  hCaptcha instead relies on app-layer session binding.

## 3. The n-token cipher (distinct, and unauthenticated)

- **Primitive:** AES-256-CTR, counter block `iv ‖ be32(counter)`.
- **Wire format:** `ciphertext(N) ‖ tag(16) ‖ iv(12) ‖ version(1)`.
- **The trailing 16-byte "tag" is NOT a MAC.** It is a *separate AES block* (the
  encrypt entry is invoked twice — once for the body, once for a 16-byte block);
  there is no GHASH/Poly1305/HMAC reachable in the module. So the n-token has
  **confidentiality but no cryptographic integrity** — CTR is malleable
  (bit-flips in ciphertext flip the same plaintext bits).
- Research note: this is why every historical brute-force that assumed GCM on the
  n-token failed — it tried to verify a GMAC tag that does not exist. Integrity of
  the n-token, to the extent it matters, is a *server-side* concern (the server
  re-derives/validates), not a client AEAD.

## 4. Key management & storage

- **Build-static keys, client-reachable.** The client must hold `response_key` to
  read server responses, so the key necessarily exists in the bundle. It is not a
  trust boundary against a client-capable adversary — only against a *passive
  network* observer (on top of TLS).
- **Obfuscated storage ≠ cryptographic protection.** In `hsw.js` the AES schedule
  is RustCrypto `fixslice32`; round keys are deobfuscated on-demand through a
  paged XOR reader and never sit as 32 contiguous plaintext bytes. This raises the
  *engineering cost* of extraction (and rotates per build), but it is
  **security-through-obscurity**: the key is fully recoverable by instrumenting
  the schedule (this repo does exactly that, verified 120/120 against the AES-256
  key schedule). See [`protocol.md`](./protocol.md) §3.

## 5. Threat-model framing — what the crypto does and doesn't do

| Adversary | Does the crypto stop them? |
|---|---|
| Passive network eavesdropper | Yes (payload confidentiality on top of TLS) |
| On-path tamperer (req/resp) | Yes (GCM AEAD rejects tampering) |
| On-path tamperer (n-token) | **No** (CTR unauthenticated client-side) |
| Client-capable adversary (runs the bundle) | **No** — holds the keys by design; crypto is not a trust boundary here |
| Replay into another context | Not by the cipher (empty AAD) — only app-layer session binding |

**Conclusion:** the request/response encryption is a *correct, standard AEAD*
whose purpose is payload confidentiality/integrity against the network, plus
*obfuscation* against casual client tampering — **not** an anti-bot control and
**not** a secret-keeping boundary. This is fully consistent with the corpus
thesis: the cipher protects the channel, the risk model protects against bots.

## 6. Design observations (defensive)

- **Strength:** standard AEAD (GCM) with 256-bit keys, per-message 96-bit IVs,
  short-lived per-build keys → sound transport confidentiality/integrity for
  req/resp.
- **Weak spots (by design, not accident):**
  - Keys are necessarily client-side ⇒ recoverable; treat as *obfuscation*.
  - Empty AAD ⇒ no cryptographic context binding (relies on app layer).
  - n-token CTR ⇒ no client-side integrity (relies on server validation).
- **If hardening were the goal:** bind context via AAD, authenticate the n-token
  (GCM or encrypt-then-MAC), and — unavoidably — accept that any client-held key
  is extractable, so never place trust in client-side confidentiality.

See [`SUMMARY.md`](./SUMMARY.md) for how this fits the whole
study, and [`protocol.md`](./protocol.md) for the wire-level
protocol.
