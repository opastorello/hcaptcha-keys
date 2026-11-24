# CAPTCHA defense architectures — comparative analysis (research notes)

Descriptive comparison of the three dominant human-verification systems, by
*defense design*. Educational/defensive; no bypass content.

---

## 1. At a glance

| Dimension | hCaptcha | Cloudflare Turnstile | reCAPTCHA (v2 / v3 / Enterprise) |
|-----------|----------|----------------------|----------------------------------|
| Primary mode | Interactive image challenge; Enterprise passive | **Non-interactive** by default (managed challenge) | v2 interactive; **v3 invisible score**; Enterprise risk API |
| Visible challenge | Image label / area-select | Rare (only on suspicion) | v2 image grid; v3 none |
| Core signal | Visual answer + behavior + reputation | Telemetry + lightweight PoW + PAT/Privacy Pass | Behavior + Google-account/cookie reputation + score |
| Proof-of-work | Yes (Hashcash+SHA-1 n-token) | Yes (JS PoW) | No explicit PoW (risk model) |
| Data labeling | **Yes** — challenges crowdsource ML labels (business model) | No | Historically yes (v2); v3 score-based |
| Privacy posture | "Privacy-first"; supports Privacy Pass | Strong (no cookies/PII marketing); Privacy Pass | Tied to Google ecosystem signals |
| Verification | server `/siteverify` | server `/siteverify` | server `/siteverify` (+ score threshold) |

## 2. Where the real barrier sits (common pattern)

All three have converged on the same insight: **the visible challenge is the
cheap outer gate; the load-bearing defense is risk scoring over behavioral +
device + reputation signals.**

- **reCAPTCHA v3** is the purest expression — *no challenge at all*, just a
  0.0–1.0 score the site thresholds. The "defense" is entirely the risk model.
- **Turnstile** is non-interactive: it runs telemetry + PoW and issues a token;
  a visible challenge appears only for already-suspicious clients.
- **hCaptcha** keeps a prominent visible challenge (partly because it monetizes
  the labeling), but Enterprise markets "~99.9% passive" — i.e. most users never
  see an image; the challenge is the fallback for risky traffic.

**Implication for research:** measuring CAPTCHA "breakability" by image-solve
rate alone is misleading for all three. The meaningful metric is end-to-end
pass rate *conditioned on* behavior/reputation — which is exactly what degrades
a pure image classifier.

## 3. Signal taxonomy (what each scores)

| Signal class | hCaptcha | Turnstile | reCAPTCHA v3 |
|--------------|:--------:|:---------:|:------------:|
| Visual correctness | ✔ (primary visible) | (fallback) | (v2 only) |
| Pointer/motion biometrics | ✔ (`motionData`) | ✔ | ✔ |
| Device fingerprint (canvas/WebGL/fonts) | ✔ | ✔ | ✔ |
| Browser-automation detection | ✔ | ✔ | ✔ |
| IP / ASN / network reputation | ✔ | ✔ | ✔ |
| Account/cookie reputation | ✔ (PST) | (Privacy Pass) | ✔ (Google) |
| Proof-of-work cost | ✔ | ✔ | ✘ |
| Cross-site history | limited (privacy) | limited (privacy) | ✔ (broad) |

## 4. Design trade-offs

- **hCaptcha**: challenge doubles as a labeling marketplace → economic incentive
  to keep a visible challenge, but adds friction. Privacy-positioned vs. Google.
- **Turnstile**: UX-first (usually invisible), privacy-first (Privacy Pass,
  minimal PII), but less "proof of human" than an actual task; leans hard on
  Cloudflare's network reputation.
- **reCAPTCHA v3**: zero friction, but shifts *all* the decision to the site
  (score threshold tuning) and depends on Google's cross-site reputation graph,
  which is the privacy criticism.

## 5. Convergent trend

The arms race moved the industry **away from "harder images"** and **toward
risk-based, increasingly invisible verification**. Consequences:

- Image-CAPTCHA robustness research is largely a *solved/weak* area academically;
  the frontier is **behavioral-biometrics spoofing detection** and
  **reputation/fingerprint evasion detection** — i.e. the defender's problem is
  now *coherence of signals*, not pixel difficulty.
- For site operators the practical guidance is identical across vendors: verify
  server-side, threshold on risk, and never treat "challenge solved" as proof of
  humanity.

## 6. Open research questions (descriptive)

1. How much of each vendor's accept/deny is explained by behavior+reputation vs.
   the visible challenge? (Requires vendor-coordinated or disclosed study.)
2. How quickly does each system adapt after a public solver technique appears
   (category rotation cadence)?
3. Privacy cost vs. detection power: does Google's cross-site graph measurably
   outperform Cloudflare's Privacy-Pass-constrained model?

See [`measurement-design.md`](./measurement-design.md) for how
these could be studied responsibly.
