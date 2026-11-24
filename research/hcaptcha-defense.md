# hCaptcha — Visual Challenge & Layered Defense (research notes)

**Scope.** Descriptive, defensive/educational analysis of how hCaptcha's
challenge-response protocol and defense architecture are *structured*, based on
protocol observation (decrypted `getcaptcha` traffic from the demo sitekey) plus
public literature. This document deliberately contains **no solver**: no image
classifier, no behavioral-signal forgery, no pass pipeline. The goal is to
understand the *security posture* — where the real barrier is and why.

---

## 1. End-to-end flow (where the layers sit)

```
checksiteconfig ──▶ features{enc_get_req} + c.req (hsw PoW challenge)
      │
   window.hsw(jwt) ──▶ PoW/n-token (Hashcash + SHA-1, build-static AES)
      │
  getcaptcha  (POST, AES-256-GCM encrypted request ⇄ encrypted response)
      │                 request  = [ hsw-token , Ext(enc client telemetry) ]
      │                 response = challenge { tasklist, question, config, oby }
      │
   (human/agent produces answers)
      │
  checkcaptcha (POST) ──▶ server grades answers + behavior + risk ──▶ pass / harder / block
```

**Key finding:** the AES-256-GCM crypto layer (per-build `request_key` /
`response_key`) is only *transport confidentiality*. It is **not** the anti-bot
barrier — it is fully reversible by protocol RE and reveals plaintext on both
sides. The actual defense lives *after* decryption, in what the server grades.

---

## 2. Visual-challenge taxonomy

| `request_type`             | Task shown                                   | Key `request_config` fields |
|----------------------------|----------------------------------------------|-----------------------------|
| `image_label_binary`       | 3×3 grid, "click each image with X"          | `answer_type: str`; per-image binary |
| `image_label_area_select`  | one image, click point(s)/area(s) ("select the shape that is different") | `shape_type: point \| bounding_box`, `min_points`/`max_points`, `min_shapes_per_image`/`max_shapes_per_image`, `overlap_threshold` |
| `image_label_multiple_choice` | pick option(s)                            | `multiple_choice_min_choices`/`max_choices` |

Observed example (decrypted response, build `4adf7ce2…`):
`request_type = image_label_area_select`, question *"Select the shape that is
different"*, `shape_type = point`, 1 shape/image.

---

## 3. Challenge object model

The decrypted `getcaptcha` response is a msgpack map:

| Field | Meaning |
|-------|---------|
| `tasklist[]` | each: `datapoint_uri` (image on `imgs*.hcaptcha.com`), `task_key`, `entities` |
| `requester_question` | localized prompt (`{"en": "..."}`) |
| `request_config` | shape/answer constraints (table above) |
| `requester_restricted_answer_set` | allowed labels |
| `key` | per-session submission token (JWT-like) |
| `oby` | opaque grading/obfuscation token echoed on submit |
| `c` | the **next** hsw PoW challenge (`{type:"hsw", req:<JWT>}`) — chained |
| `normalized`, `tjf` | flags |

The **sent** request's encrypted telemetry (msgpack `Ext(18)` → AES-GCM) carries
`v`, `sitekey`, `host`, `motionData`, `pdc`/`pem` (timing counters), `n` (proof
blob), `ws`, `clientOptions`, `psd`. This is the behavioral evidence the server
scores (see §5) — enumerated here as *schema*, not as a forging recipe.

---

## 4. Dual purpose: human-in-the-loop data labeling

hCaptcha is also a **data-labeling marketplace**. A challenge batch mixes:

- **ground-truth** tasks (already labeled) — used to *grade you*;
- **unlabeled** tasks — your answers become training labels sold to customers.

Research angle: estimate the ground-truth : unlabeled ratio per batch, and how
grading tolerates disagreement on unlabeled items. This is the economic reason
the challenge exists at all, independent of bot defense.

---

## 5. The layered defense — the real barrier

Solving the image is necessary but **not sufficient**. The server fuses signals:

| Layer | Signal | Why it matters |
|-------|--------|----------------|
| **Visual** | correct answer vs. ground truth | Weak alone (see §6); gates obvious bots |
| **Behavioral** | `motionData` (pointer trajectory, timing, event cadence), interaction entropy | Distinguishes human-like motion from scripted/teleported input |
| **Device fingerprint** | UA, canvas/WebGL, fonts, screen, timezone coherence | Catches headless/automation stacks and inconsistent spoofs |
| **Reputation / risk** | IP, ASN, cookie history, cross-site signals, PST tokens | A low-trust client gets *harder* challenges or is blocked despite a correct answer |
| **Proof-of-work** | hsw Hashcash+SHA-1 | Imposes *cost*, not detection — rate-limits automation economically |

**Thesis:** the design intentionally makes the *visual* layer the cheap outer
gate and the *behavioral + reputation* layers the load-bearing defense. That is
why "resolver a imagem ≠ passar," and why even commercial solvers show unstable
end-to-end success that collapses on each hCaptcha update.

---

## 6. Robustness literature (high level)

- Image CAPTCHAs are broadly considered **weak** against modern CNNs / object
  detectors; multiple published works report high solve rates on grid-image and
  object-selection captchas.
- Consequence: the industry shifted defense from *challenge difficulty* toward
  **risk-based / invisible** verification (reCAPTCHA v3, Cloudflare Turnstile,
  hCaptcha Enterprise "99.9% passive"). The visible challenge is increasingly a
  fallback for *already-suspicious* traffic.
- hCaptcha counters generic models with **category rotation** and adversarial
  perturbation of challenge images — a moving target that degrades any fixed
  classifier over time.

Takeaway for a robustness study: the interesting, *defensible* questions are
about the **system**, not the pixels — e.g. "what fraction of the pass/fail
decision is explained by behavior+reputation vs. the image?"

---

## 7. Defensive takeaways (for site operators)

- Don't treat a solved challenge as "human." Lean on the **risk score** and
  server-side verification (`/siteverify`), set appropriate difficulty, and use
  Enterprise risk signals where abuse is high-value.
- Monitor pass-rate anomalies per ASN/IP and token reuse.
- Accessibility: offer the official **hCaptcha Accessibility** path so the
  defense doesn't punish legitimate users who can't do image tasks.

---

## 8. Where this research stops

In scope (this document): protocol structure, challenge taxonomy, data-labeling
model, layered-defense analysis, literature summary.

Out of scope (not built here): training an image classifier for the challenge,
synthesizing plausible `motionData`, or any submission pipeline whose purpose is
to *pass* the challenge. Those constitute an operational evasion tool regardless
of framing, and are not part of this study.
