# hCaptcha & the CAPTCHA defense landscape — executive summary

A synthesis of this repository's research notes on how hCaptcha (and its peers)
are *built* and where their anti-bot strength actually lives. Descriptive and
defensive throughout: it characterizes the system; it contains no solver, no
behavioral-signal synthesis, and no bypass.

---

## Abstract

We reverse-engineered the hCaptcha client protocol end-to-end — the asset/build
model, the AES-256-GCM request/response crypto, the msgpack challenge schema, and
the Hashcash/SHA-1 proof-of-work — and verified it against live traffic (a real
`getcaptcha` round-trip decrypted in both directions with independently extracted
per-build keys). We then placed those mechanisms inside hCaptcha's layered defense
and compared it to Cloudflare Turnstile and reCAPTCHA v3/Enterprise. The central
finding is consistent across every layer: **the transport, crypto, and PoW are
fully characterizable and reversible, but none of them is the barrier. The
anti-bot decision is a risk score over behavioral biometrics, device fingerprint,
and network/account reputation — and the visible challenge is the cheap outer
gate, not the lock.**

## Scope & method

- **Observation:** decrypting real demo-sitekey traffic; per-build key recovery by
  structural instrumentation of the WASM (no hard-coded indices; survives the
  frequent build rotation).
- **Measurement:** an hourly CI records the crypto layer per build
  (`data/keys.json` + `data/history/`) — the one continuous, low-rate, public-asset-
  only study that is fully safe to run.
- **Analysis:** layered-defense decomposition + a four-way vendor comparison, all
  from public behavior and literature.
- **Out of scope (by design):** image classification, `motionData` synthesis, and
  any pass/submission pipeline — i.e. the operational evasion tool.

## Key findings

1. **Crypto ≠ defense.** hCaptcha's AES-256-GCM (`iv‖ct‖tag`, two build-static
   keys) is transport confidentiality. It is reversible by protocol RE and yields
   plaintext on both sides. [`protocol`], [`defense` §1]
2. **The challenge is also a data-labeling product.** Batches mix ground-truth
   (grading you) and unlabeled (you labeling Intuition Machines' data), which is
   an independent economic reason the visible task exists. [`defense` §4]
3. **Image CAPTCHAs are academically weak.** Modern CNN/object detectors solve
   them at high rates; the industry responded by moving defense to risk-based /
   invisible verification. Solving the image is necessary-not-sufficient.
   [`defense` §6], [`comparison`]
4. **PoW is a tax, not a detector.** Hashcash/SHA-1 at modest difficulty costs
   sub-second and cannot distinguish human from bot; it throttles *volume*, and
   SHA-1 is trivially GPU-accelerated, so its deterrence is weak on its own.
   [`pow`]
5. **The load-bearing layer is behavioral + reputation coherence.** `motionData`
   is scored *relationally* (kinematics, timing entropy, device coherence,
   cross-checked against perf counters), so "fields populated" is not humanity;
   replay and too-smooth synthetic motion are themselves tells. [`motiondata`]
6. **Every major vendor converged on the same thesis.** Turnstile is near-fully
   passive (no image, Privacy-Pass reputation); reCAPTCHA v3 is a bare score;
   reCAPTCHA Enterprise exposes *reason codes* (`AUTOMATION`, …) that publicly
   confirm the automation-tell taxonomy. The axis that distinguishes them is the
   **privacy cost of their reputation signal**, not challenge difficulty.
   [`turnstile`], [`recaptcha-enterprise`], [`comparison`]

## Central thesis

> The puzzle is theater; the risk model is the defense. Anything a client can
> compute and send — crypto, PoW, a correct image answer — is reproducible and
> therefore not where the security lives. What is hard to fake is the *coherent
> statistical fingerprint of a real human on a real device with real history*,
> judged jointly. That is why protocol RE (this repo) is tractable and complete,
> while a robust autonomous solver is not a crypto problem but a behavioral- and
> reputation-forgery problem — the part this research deliberately does not build.

## Document index

| # | Doc | Topic |
|---|-----|-------|
| 1 | [`protocol.md`](protocol.md) | Client protocol + crypto whitepaper |
| 2 | [`crypto-analysis.md`](crypto-analysis.md) | Encryption/decryption construction analysis |
| 2b | [`ntoken-residual.md`](ntoken-residual.md) | The n-token key — the open residual + next experiment |
| 3 | [`hcaptcha-defense.md`](hcaptcha-defense.md) | Visual-challenge taxonomy + layered defense |
| 4 | [`motiondata-signal.md`](motiondata-signal.md) | Behavioral signal analysis (detection view) |
| 5 | [`pow-hsw.md`](pow-hsw.md) | hsw proof-of-work cost analysis |
| 6 | [`captcha-comparison.md`](captcha-comparison.md) | hCaptcha vs Turnstile vs reCAPTCHA v3 |
| 7 | [`turnstile-architecture.md`](turnstile-architecture.md) | Turnstile architecture deep-dive |
| 8 | [`recaptcha-enterprise.md`](recaptcha-enterprise.md) | reCAPTCHA Enterprise signal analysis |
| 9 | [`recaptcha-v3-why-opaque.md`](recaptcha-v3-why-opaque.md) | Why v3 resists client-side extraction |
| 10 | [`related-work.md`](related-work.md) | hCaptcha RE/solver ecosystem (by layer + activity) |
| 11 | [`measurement-design.md`](measurement-design.md) | Responsible study methodology |

## Conclusion & stance

For **site operators**: verify server-side, threshold on risk, weight reputation,
bind sessions against replay, and never treat "challenge solved" as "human"; offer
the official accessibility path so the defense does not punish legitimate users.

For **researchers**: the tractable, publishable surface is the system — protocol,
crypto rotation, PoW economics, signal taxonomy, and vendor comparison. Questions
about anti-bot *efficacy* require controlled, disclosed, vendor-aware experiments
([`measurement-design`]), not a scaled solver.

This repository characterizes the mechanism and documents the defense design.
That is where the research ends — on purpose.
