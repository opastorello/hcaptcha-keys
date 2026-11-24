# reCAPTCHA Enterprise — signal-level analysis (research notes)

Descriptive comparison of reCAPTCHA Enterprise against the v3 baseline and the
hCaptcha / Turnstile models, at the level of *what signals it exposes and
scores*. Defensive/educational; based on public documentation and behavior.

---

## 1. v3 baseline vs Enterprise

reCAPTCHA **v3** returns a single opaque **score** (0.0–1.0) per action, plus an
action label, verified server-side via `siteverify`. The site thresholds the
score. That's essentially the whole interface — detection logic is Google's
black box.

reCAPTCHA **Enterprise** keeps the invisible, score-based core but exposes a
much richer **assessment** object and adds fraud/account products on top:

| Capability | v3 | Enterprise |
|-----------|:--:|:----------:|
| Risk score per action | ✔ | ✔ (finer) |
| **Reason codes** (why risky) | ✘ | ✔ (e.g. `AUTOMATION`, `UNEXPECTED_ENVIRONMENT`, `TOO_MUCH_TRAFFIC`, `LOW_CONFIDENCE_SCORE`) |
| Account Defender (ATO signals) | ✘ | ✔ |
| Password-leak / credential-stuffing detection | ✘ | ✔ |
| Payment/transaction fraud signals | ✘ | ✔ (Fraud Prevention) |
| Mobile app SDK + attestation | limited | ✔ (Play Integrity / DeviceCheck-style) |
| WAF / reCAPTCHA-in-front integration | ✘ | ✔ |
| MFA / step-up hooks | ✘ | ✔ |

## 2. Signal model (what Enterprise scores)

Beyond v3's passive behavior+fingerprint score, Enterprise fuses:

- **Behavioral telemetry** — interaction cadence, timing, navigation patterns.
- **Device & environment** — browser/app fingerprint, automation markers,
  environment anomalies (headless, emulator, inconsistent stack).
- **Google cross-site reputation** — the account/cookie graph across Google's
  footprint; the biggest asymmetric signal (and the central **privacy** critique,
  since it is *linkable*, unlike Turnstile's Privacy Pass).
- **Account signals (Account Defender)** — login-pattern anomalies, known-breach
  credentials, takeover indicators tied to a user id the site supplies.
- **Transaction context (Fraud Prevention)** — cart/payment risk for commerce
  flows, chargeback/abuse likelihood.
- **Mobile attestation** — app/device integrity on native SDKs.

The output is an **assessment** with a score **and** reason codes, letting the
site branch (allow / step-up MFA / block) per action instead of a bare threshold.

## 3. Position in the four-way comparison

| Aspect | reCAPTCHA v3 | reCAPTCHA Enterprise | hCaptcha | Turnstile |
|--------|:---:|:---:|:---:|:---:|
| Default UX | invisible score | invisible score + assessment | visible task (+ passive Enterprise) | invisible |
| Reason codes / explainability | ✘ | **✔** | limited | limited |
| Account-takeover product | ✘ | ✔ | ✘ | ✘ |
| Fraud/payment product | ✘ | ✔ | ✘ | ✘ |
| Reputation primitive | Google graph (linkable) | Google graph (linkable) | PST / Privacy Pass | Privacy Pass |
| Data labeling | ✘ | ✘ | ✔ | ✘ |
| Proof-of-work | ✘ | ✘ | ✔ (Hashcash/SHA-1) | ✔ (JS) |

## 4. Research implications

- Enterprise is the clearest statement that the market treats human-verification
  as a **risk/fraud analytics** problem, not a puzzle: the value is in **reason
  codes + account/transaction context**, i.e. *why* a request is risky and *what
  to do*, far beyond "solve this."
- The explainability (reason codes like `AUTOMATION`) is useful for a defensive
  study: it is a vendor-published taxonomy of the *automation tells* detectors
  look for, which aligns with the behavioral/fingerprint-coherence thesis in
  [`RESEARCH-motiondata-signal.md`](./RESEARCH-motiondata-signal.md).
- Privacy trade-off remains the sharpest axis: Google's linkable cross-site graph
  is the most powerful reputation signal of the four systems and the most
  privacy-invasive — the inverse of Turnstile's Privacy-Pass stance.

See [`RESEARCH-captcha-comparison.md`](./RESEARCH-captcha-comparison.md) for the
base three-way comparison this extends.
