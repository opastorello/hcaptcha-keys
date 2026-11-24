# hsw proof-of-work — cost analysis (research notes)

Descriptive analysis of hCaptcha's `window.hsw(jwt)` proof-of-work: what it is,
what it costs, and what security role it actually plays. Defensive/educational.

---

## 1. What it is

Confirmed empirically (see `src/hcaptcha/hsw_pow.py`): the PoW is **Hashcash v1
over SHA-1** (`rust-hashcash` 0.3.3, `sha1` feature). Evidence: the SHA-1 round
constants `0x5A827999` / `0x6ED9EBA1` appear as `i32.const` literals in the
`hsw.js` WASM (once per round). The xxHash primes a community post named are
*not* in the WASM for PoW (xxHash is used for the fingerprint hash, not the
stamp).

## 2. Stamp format

Standard Hashcash v1:

```
1:bits:date:resource:ext:rand:counter
```

| Field | Value in hCaptcha |
|-------|-------------------|
| `bits` | leading-zero-bit **difficulty** (from the challenge JWT) |
| `date` | `YYYYMMDD` (rust-hashcash default, UTC) |
| `resource` | the JWT payload re-serialized as compact JSON |
| `ext` | empty |
| `rand` | 8 alphanumeric chars (salt) |
| `counter` | searched nonce, incremented from 0 |

Valid when `SHA1(stamp)` begins with `bits` zero bits. The challenge JWT
(`c.req`) carries the difficulty + resource + an expiry (`e`); exact field names
(`d`, `c`, `s`, …) vary per build, so tooling reads them structurally.

## 3. Cost model

Finding a stamp with `b` leading zero bits is a memoryless search: each SHA-1
trial succeeds with probability `2^-b`, so the **expected** number of hashes is
`2^b` (geometric distribution; worst-case unbounded, variance high).

| Difficulty `b` | Expected hashes `2^b` | ~Time @ 5M h/s (JS) | ~Time @ 300M h/s (native) |
|---:|---:|---:|---:|
| 12 | 4,096 | <1 ms | <1 ms |
| 16 | 65,536 | ~13 ms | <1 ms |
| 20 | 1,048,576 | ~0.2 s | ~3 ms |
| 24 | 16,777,216 | ~3.4 s | ~56 ms |
| 28 | 268,435,456 | ~54 s | ~0.9 s |

Verification is a **single** SHA-1 — the asymmetry Hashcash is built on: cheap
to check server-side, more expensive to produce.

## 4. What security role it actually plays

- **It is a cost function, not a detector.** The PoW cannot tell a human from a
  bot — both compute the same stamp. Its job is to make *high-volume* requests
  economically expensive, i.e. **rate-limiting by burned CPU**.
- **The difficulty is deliberately modest.** hCaptcha cannot set `b` high enough
  to deter a motivated attacker without punishing real users on weak devices.
  At the typical difficulties the cost is sub-second — a speed bump, not a wall.
- **Asymmetry is weak here.** Unlike memory-hard PoW (scrypt/Argon2), SHA-1
  Hashcash is trivially accelerated on GPUs/ASICs, so an attacker's per-stamp
  cost is far below a browser's. The PoW therefore throttles *naive* abuse but
  not resourced automation.
- **Chaining adds friction, not detection.** Because each response embeds the
  *next* `c` challenge, a session must pay PoW repeatedly — this raises the
  aggregate cost of long automated sessions without identifying them.

## 5. Research takeaway

The hsw PoW is best understood as **economic throttling layered under the real
defense**, consistent with the thesis across these notes: detection lives in
behavior + reputation, while PoW only taxes volume. For a cost study, the
interesting metric is *aggregate PoW spend per successful session* (difficulty ×
chaining depth) versus the attacker's marginal hash cost — which quantifies
exactly how little deterrence a low-bit SHA-1 Hashcash provides on its own.

See [`hcaptcha-defense.md`](./hcaptcha-defense.md) for how PoW
sits within the layered model.
