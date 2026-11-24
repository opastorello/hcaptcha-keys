# Measurement study designs (research methodology)

How the open questions about hCaptcha's challenge could be studied
**responsibly and descriptively**. This document is research *design* — it
defines questions, sampling, metrics, and ethics. It deliberately does **not**
ship a live mass-collector, an image classifier, or any grading-probe pipeline,
because those are the data/solve stages of an evasion tool and also stress a
third party's infrastructure.

---

## 0. Ethics & constraints (read first)

- **ToS / infra load:** mass-polling `getcaptcha`/`checkcaptcha` violates
  hCaptcha's terms and burdens their service. Any empirical work should use the
  **official demo/test sitekeys**, stay at hand-scale sample sizes, and prefer
  **vendor-coordinated** access or **published datasets**.
- **No ground-truth answering at scale:** estimating grading behavior requires
  submitting answers; doing that in volume is operationally a solver. Treat such
  measurement as **vendor-side or disclosed-research only**.
- **Responsible disclosure:** findings about weaknesses go to hCaptcha /
  Intuition Machines via their disclosure channel, not into an operational tool.

---

## Study 1 — Ground-truth vs. unlabeled ratio per batch

**Question.** What fraction of a challenge batch is scored against known labels
(grading you) vs. unlabeled (you labeling their data)?

**Why it's hard.** The payload does **not** mark which tasks are ground-truth.
The distinction only manifests in *grading behavior* (you can answer unlabeled
tasks "wrong" and still pass if the ground-truth subset is correct).

**Responsible design.**
- Instrument on a **test sitekey** only; small N.
- Observe `tasklist` sizes and `request_config` across a modest sample to
  characterize batch *shape* (purely descriptive — no answering needed).
- The grading-tolerance probe (answer-perturbation) is **vendor-coordinated
  only**; document the *method* here, do not run it at scale.

**Metrics.** batch size distribution; images-per-batch; config variety. (Shape
metrics are collectible descriptively; the GT:unlabeled split itself needs
vendor cooperation to measure without an answering harness.)

---

## Study 2 — Challenge-type frequency & category rotation

**Question.** How do `request_type`, `shape_type`, and question categories
distribute, and how fast does the category set rotate?

**Responsible design.**
- Demo-sitekey, hand-scale periodic observation (not a high-rate scraper).
- Record only metadata: `request_type`, `request_config`, `requester_question`
  text, counts — **not** the challenge images (avoid building a labeled corpus).
- Timestamp each observation to chart category turnover.

**Metrics.** type histogram; question-category turnover rate (new categories /
week); config-parameter ranges. Expected (from literature): frequent category
rotation + adversarial image perturbation to degrade generic models.

---

## Study 3 — Defense-weight attribution (the key question)

**Question.** How much of the accept/deny decision is explained by the visual
answer vs. behavior vs. reputation?

**Why it matters.** This is the thesis of the defense analysis — if behavior +
reputation dominate, "solving the image" is not the barrier.

**Responsible design.** This is inherently a **controlled-experiment /
vendor-coordinated** study (you must vary one signal while holding others
fixed, which means interacting with grading). Document as a *proposed protocol*:
- Hold a fixed, consented test environment (your own site + test keys).
- Vary network reputation (clean vs. flagged egress) and observe challenge
  difficulty / pass behavior **without** automating challenge answers.
- Report correlation between reputation inputs and challenge escalation.

**Metrics.** challenge-difficulty escalation vs. reputation inputs; pass-rate
sensitivity to behavioral plausibility (measured, not forged).

---

## Study 4 — Protocol / crypto-layer longitudinal record

**Question.** How do the build hash, AES keys, wire format, and function
structure evolve over time?

**Responsible design.** This is already implemented, cleanly: the hourly CI in
this repo records `data/keys.json` + `data/history/<version>.json` per build
(crypto-layer metadata only). It's descriptive, low-rate (one check/hour), and
touches only public asset URLs.

**Metrics.** build-rotation cadence; key-set stability; wire-format drift;
cipher changes (e.g. GCM vs. CTR per path). This is the one study here that is
fully safe to run continuously, and it's the empirical backbone for the protocol
whitepaper.

---

## Summary

| Study | Safe to run here? | Why |
|-------|-------------------|-----|
| 1 GT:unlabeled ratio | shape metrics only | split needs answering → vendor-coordinated |
| 2 Type frequency | metadata-only, hand-scale | avoid image corpus / high-rate scraping |
| 3 Defense attribution | design only | requires controlled grading interaction |
| 4 Crypto longitudinal | **yes (CI already does it)** | public assets, 1/hour, metadata only |

The honest research takeaway stays constant: the *crypto and protocol* are fully
characterizable (Study 4, done), but the *anti-bot efficacy* lives in behavior +
reputation, which can only be studied responsibly through controlled,
disclosed, vendor-aware experiments — not by scaling up a solver.
