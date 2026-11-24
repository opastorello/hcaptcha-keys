# Cloudflare Turnstile — architecture deep-dive (research notes)

Descriptive analysis of Turnstile's verification model and client wire shape,
for comparison with hCaptcha. Defensive/educational; based on public behavior
and documentation. No bypass content.

---

## 1. Design philosophy

Turnstile is **non-interactive by default**: it aims to issue a verification
token *without* showing the user a task. The visible "managed challenge" (and,
rarely, an interactive step) appears only for traffic Cloudflare's risk model
already distrusts. Contrast with hCaptcha, whose visible image challenge is also
a **data-labeling product** — Turnstile has no labeling business, so it has no
incentive to show tasks, and leans entirely on passive signals + network
reputation.

## 2. Client wire shape (high level)

| Stage | What happens |
|-------|--------------|
| Widget load | `challenges.cloudflare.com/turnstile/.../api.js` loads; renders an iframe widget bound to a **sitekey** |
| Challenge fetch | the widget requests a managed-challenge payload (obfuscated JS problem + telemetry collectors) from `challenges.cloudflare.com` |
| Solve (client) | the browser runs the JS challenge: **lightweight proof-of-work** + environment/telemetry collection, entirely in-page |
| Token issue | on success the widget yields a **response token** (`cf-turnstile-response`, ~short-lived) to the host page |
| Server verify | host posts token to `/turnstile/v0/siteverify` with its secret; Cloudflare returns pass/fail (+ optional metadata) |

Compared to hCaptcha there is **no `getcaptcha` image batch** and usually **no
AES-encrypted challenge-content round-trip** — the "challenge" is a JS/PoW +
telemetry computation, not an image task to answer.

## 3. Signal model

Turnstile scores, without a visible task:

- **Environment / fingerprint**: browser APIs, rendering behavior, automation
  tells (headless markers, inconsistent env).
- **Behavioral telemetry**: lightweight interaction/timing signals.
- **Proof-of-work**: a JS compute cost to rate-limit cheap automation.
- **Network reputation**: Cloudflare's global view of the IP/ASN (its biggest
  asymmetric advantage — it sits in front of a large fraction of the web).
- **Privacy Pass**: Turnstile can issue/redeem Privacy Pass tokens so returning
  "known-good" clients skip work without cross-site tracking.

## 4. Privacy Pass (the notable primitive)

Privacy Pass (RFC 9578 family) lets a client redeem **anonymous, unlinkable
tokens** proving "I was vetted before" without revealing *which* prior session.
Turnstile uses this to reward reputation while limiting cross-site tracking —
architecturally different from reCAPTCHA v3, which leans on Google's
*linkable* cross-site cookie/account graph. This is the clearest privacy-vs-
detection-power trade-off in the three-way comparison.

## 5. Turnstile vs hCaptcha vs reCAPTCHA v3 — wire/behavior

| Aspect | Turnstile | hCaptcha | reCAPTCHA v3 |
|--------|-----------|----------|--------------|
| Default UX | invisible / managed | visible image task | invisible |
| Challenge content round-trip | JS/PoW + telemetry (no image batch) | AES-GCM `getcaptcha` image batch | none (score only) |
| Explicit crypto round-trip | minimal | **yes** (per-build AES-256-GCM req/resp) | none |
| Proof-of-work | yes (JS) | yes (Hashcash+SHA-1 n-token) | no |
| Reputation source | Cloudflare network | hCaptcha + PST | Google cross-site graph |
| Anonymity primitive | Privacy Pass | PST / Privacy Pass | linkable Google signals |
| Data labeling | no | **yes** | no (v3) |

## 6. Research implications

- Turnstile is the cleanest example of the industry thesis in these notes: **the
  barrier is risk + reputation + telemetry coherence, not a human task.** There
  is effectively no "image to solve," so a solver framing does not even apply —
  the only surface is *looking like a trustworthy client*, which is detection of
  automation, not classification of pixels.
- For a comparative robustness study, Turnstile isolates the "passive signal"
  variable: whatever success/failure it shows is almost purely a function of
  fingerprint/behavior/reputation coherence — a useful control against hCaptcha
  (task + passive) and reCAPTCHA v3 (passive + Google graph).

See [`captcha-comparison.md`](./captcha-comparison.md) for the
three-way signal table and [`measurement-design.md`](./measurement-design.md)
for how to study these responsibly.
