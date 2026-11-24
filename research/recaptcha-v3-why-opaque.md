# Why reCAPTCHA v3 resists client-side extraction (research notes)

Why the extraction we did against hCaptcha (recover per-build keys, decrypt the
challenge round-trip) has **no equivalent** against reCAPTCHA v3 — and why that
is an architectural property, not a gap in effort. Descriptive/defensive.

---

## 1. The asymmetry in one sentence

hCaptcha became transparent to us because it **must** ship a decryptable
challenge and the key to read it on the client; reCAPTCHA v3 ships **neither a
challenge nor a client-held secret**, because its entire verdict is computed
server-side as an opaque risk score.

## 2. Side-by-side

| Property | hCaptcha | reCAPTCHA v3 |
|---|---|---|
| Visible / fetched challenge | yes (encrypted `getcaptcha` batch) | **none** |
| Encrypted challenge-content round-trip | yes (AES-256-GCM req/resp) | **none** |
| Client-held secret | **yes** — decrypt key must be present to read server responses | **no** — nothing to extract |
| Output to client | plaintext challenge (question, images, tokens) | an **opaque token** only |
| Where "is this human?" is decided | partly client-visible protocol + server grading | **entirely server-side** (0.0–1.0 score) |
| What RE yields | keys + plaintext + protocol | the signal *collector*, not a secret or verdict |

## 3. The three structural reasons

1. **No client secret exists.** hCaptcha's client is *required* to hold the AES
   key — otherwise it cannot decrypt the server's challenge response. That
   necessity is what makes the key recoverable. reCAPTCHA v3 never needs a secret
   on the client because it never decrypts anything for the client; there is no
   key to lift.

2. **The decision is server-side and opaque.** v3 emits a token; the risk model
   that turns signals into a score runs in Google's backend and is never shipped.
   The site reads the score through `siteverify` (with its secret). There is no
   "challenge answer" to recover because there is no challenge.

3. **The signal path is one-way.** v3's obfuscated client (a bytecode-VM
   interpreter) *collects* telemetry — behavior, fingerprint, environment — and
   **sends** it to Google encoded. Reverse-engineering the VM reveals *what it
   collects and how it encodes*, but not a secret and not the verdict. The
   heaviest signal — Google's cross-site reputation graph — is server-side data
   you simply do not have.

## 4. What is and isn't obtainable

| Target | hCaptcha | reCAPTCHA v3 |
|---|:--:|:--:|
| Per-build crypto keys | ✔ recoverable | — none exist |
| Decrypt challenge content | ✔ | — no challenge |
| Characterize client signal collection | ✔ | ✔ (RE-able, but obfuscated/VM) |
| Obtain the risk verdict / scoring logic | partial | ✘ server-side, opaque |
| Interpret the response token client-side | ✔ (it's a real challenge) | ✘ opaque, `siteverify`-only |

## 5. The token is a reference, not a payload

The `g-recaptcha-response` token can be captured but not "decrypted" into meaning
on the client: it is a signed/encrypted reference to a **server-side assessment**,
designed so only Google (via the site's secret) can resolve it. Capturing it
tells you nothing a solver could use; it is not a challenge you answered, it is a
pointer to a decision already made elsewhere.

## 6. The irony — and the trade-off

reCAPTCHA v3 is **more resistant to this class of analysis precisely because it
holds nothing on the client.** hCaptcha's transparency to us is a direct
consequence of its design needs (a visible, gradable challenge — partly driven by
its data-labeling business). v3 moved everything server-side, so there is no
key, no plaintext, no challenge to recover.

The cost of that choice is **privacy**: v3's power comes from Google's *linkable*
cross-site reputation graph — the central criticism of the product, and the
opposite of Turnstile's Privacy-Pass stance (see
[`captcha-comparison.md`](./captcha-comparison.md) and
[`recaptcha-enterprise.md`](./recaptcha-enterprise.md)).

## 7. Takeaway

This is not a failed extraction — there is nothing client-side to extract. v3's
barrier is 100% server-side risk scoring, which reinforces the thesis of the
whole corpus (see [`SUMMARY.md`](./SUMMARY.md)):

> What a client can compute and send is reproducible and therefore not where the
> security lives. v3 simply removes the client-side surface entirely and keeps the
> decision on the server — the strongest version of "the puzzle is theater, the
> risk model is the defense."
