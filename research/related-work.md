# Related work — the hCaptcha RE / solver ecosystem

A descriptive survey of public projects that work with hCaptcha, organized by
**which layer of the system they attack**. This maps the ecosystem onto the
layered-defense thesis (see [`SUMMARY.md`](./SUMMARY.md) and
[`hcaptcha-defense.md`](./hcaptcha-defense.md)) and situates this repository's
contribution. Descriptive/defensive; we characterize public projects, we do not
integrate or run solvers.

---

## 1. The layers, and who attacks each

hCaptcha is defense-in-depth; public projects cluster cleanly by the layer they
target:

```
  ┌─────────────────────────────────────────────────────────────┐
  │ L1  Transport / crypto / protocol  ← fully characterizable   │  ← RE projects
  │ L2  Proof-of-work (hsw Hashcash)   ← a cost, not a gate       │
  │ L3  Visual challenge answer        ← ML / VLM / human farms   │  ← "solvers"
  │ L4  Behavioral + fingerprint       ← anti-detect browsers     │  ← evasion stacks
  │ L5  Reputation / risk (server)     ← not client-reachable     │  ← (nobody: opaque)
  └─────────────────────────────────────────────────────────────┘
```

## 2. L1–L2 — crypto / protocol reverse engineering

| Project | Approach | Notes |
|---|---|---|
| **this repo** (`opastorello/hcaptcha-keys`) | **fixslice bitslice *write* interception** of the u32 virtual-memory writer + AES-256 key-schedule inversion (self-verified 120/120) + module-oracle confirmation; structural detection; hourly CI | recovers both per-build keys, publishes vastien-schema JSON |
| `Implex-ltd/hcaptcha-reverse` | WASM-level RE of the `hsw`/`hsj` bundles; crate inventory (incl. `rust-hashcash`), PoW + fingerprint analysis | the source we cross-referenced for the Hashcash/SHA-1 PoW identification ([`pow-hsw.md`](./pow-hsw.md)) |
| `CircuitSavage/hcaptcha-hsj-hsw-reversed` | key extraction + per-build archive (different output schema) | the upstream this project forked from |
| `vastien/hcaptcha-keys` | **publishes** per-build keys on a schedule (private extractor) | the key-repo pattern this project reproduced independently |

**Observation:** at L1–L2 the system is *transparent* — keys, wire format, and
PoW are all recoverable. These projects differ mainly in *extraction technique*
(read- vs write-interception, static vs live) and *packaging* (library vs
published key feed). This repo's distinction is the **write-interception +
self-verifying schedule inversion**, which survives build rotation by structural
fingerprint rather than hard-coded indices.

## 3. L3 — the visual-answer layer (solvers)

This is where the arms race actually lives, and its evolution is instructive:

| Project | Technique | Era |
|---|---|---|
| `JimmyLaurent/hcaptcha-solver` (JS) | early image-recognition (SineCaptcha/Futei lineage) | 2022, classical CV |
| `CaptchaAgent/hcaptcha-model-factory` (PyTorch) | **train per-category ONNX classifiers** for `image_label_binary`; cluster-based auto-labeling | fixed-model era |
| `QIN2DIM/hcaptcha-challenger` (Python) | **multimodal LLM / VLM** answers the challenge, generalizing across types zero-shot | current, LLM era |
| `aw1875/puppeteer-hcaptcha`, `JustTalDevelops/go-hcaptcha` | browser-automation harnesses that plug a recognizer into the flow | — |

**The key trend — classifier → VLM.** `model-factory` represents the old
approach: train a dedicated ONNX model *per challenge category*. hCaptcha's
defensive **category rotation** (new object classes, adversarial perturbation)
degrades fixed classifiers, forcing constant retraining. `hcaptcha-challenger`'s
move to a **general multimodal LLM** is a direct counter: a VLM answers novel
categories without retraining, because it generalizes. This is the single
clearest signal in the ecosystem that **the visual layer is, in isolation,
increasingly weak** — generic vision models now cover it.

## 3.1 Temporal signal — the solver graveyard

Project *activity* is itself evidence. Mapping age vs. last commit (as of
2026-11):

| Project | Layer / technique | Created | Last push | Status |
|---|---|---|---|---|
| `QIN2DIM/hcaptcha-challenger` | L3 — **multimodal LLM** | 2022-02 | 2026-11 | **ACTIVE** |
| `botswin/BotBrowser` | L4 — anti-detect fingerprint | 2024-09 | 2026-11 | **ACTIVE** |
| `Implex-ltd/hcaptcha-reverse` | L1 — protocol RE | 2023-09 | 2025-09 | stale (~15mo) |
| `avengy/hcaptcha-bypass-discord` | L2/L3 — http replay | 2021-08 | 2025-11 | stale (~13mo) |
| `CaptchaAgent/hcaptcha-model-factory` | L3 — **fixed ONNX classifier** | 2022-05 | 2023-11 | **DEAD** (~3y) |
| `JimmyLaurent/hcaptcha-solver` | L3 — classical CV (SineCaptcha) | 2020-06 | 2022-12 | **DEAD** (~4y) |
| `aw1875/puppeteer-hcaptcha` | L3 — automation harness | 2021-03 | 2022-12 | **DEAD** (~4y) |
| `JustTalDevelops/go-hcaptcha` | L3 — recognizer harness | 2021-03 | 2023-01 | **DEAD** (~4y) |

**The graveyard is not random — it is exactly the approaches hCaptcha's defense
evolution killed:**

- **Fixed per-category classifiers** (`model-factory`) and **classical CV**
  (`JimmyLaurent`, the SineCaptcha lineage) died ~3–4 years ago: **category
  rotation** made any fixed model obsolete faster than it could be retrained.
- **HTTP-replay / automation harnesses** (`puppeteer-hcaptcha`, `go-hcaptcha`)
  died because **build rotation + behavioral/fingerprint checks** broke static
  flows.
- **Only two postures stay alive:** a **generalizing multimodal LLM**
  (`hcaptcha-challenger`) that survives category rotation by not being
  category-specific, and an **anti-detect fingerprint browser** (`BotBrowser`)
  operating at L4. Both are actively maintained *because* they sit on the two
  layers that still move.

**Why L1 RE goes "stale" without being dead:** protocol RE (`Implex`) ages
gracefully — once the construction is understood it needs few updates. The
exception is the *key layer*, which rotates per build; this repo stays ACTIVE
not by chasing a moving classifier but by an hourly CI that re-extracts the
rotating keys — a maintenance model matched to *what actually changes* (keys),
not to an adversary that adapts (vision/behavior).

## 4. L4 — behavioral / fingerprint layer

| Project | Role |
|---|---|
| `botswin/BotBrowser` (2.6k★) | anti-detect browser core with unified fingerprint spoofing |
| `vinyzu-archive/Botright` | automation framework with fingerprint/behavior shaping |
| (Camoufox, used in this study) | engine-level fingerprint spoofing for RE |

These exist precisely because **solving the image is not sufficient** (§5 of the
defense doc): the request must also *look like a real browser* and carry
plausible behavior. L4 is the hard, ongoing frontier.

## 5. L5 — reputation / risk

No public project "solves" L5, because it is **server-side and opaque** — there
is nothing client-reachable to reverse (the same reason reCAPTCHA v3 resists
extraction entirely, see [`recaptcha-v3-why-opaque.md`](./recaptcha-v3-why-opaque.md)).
This is the layer that ultimately decides, and the one no amount of client RE
can touch.

## 6. What the ecosystem shape tells us

- **L1–L2 are solved and transparent** — many projects, differing only in
  technique/packaging (this repo included).
- **L3 migrated classifier → multimodal LLM**, i.e. the visual puzzle is now
  covered by general vision models; difficulty is no longer the defense.
- **L4 is the active arms race** (anti-detect browsers vs. fingerprint/behavior
  detection).
- **L5 is untouchable from the client** and is where the real decision sits.

This distribution *is* the layered-defense thesis, observed empirically in who
builds what: the further from the pixels and toward reputation you go, the fewer
projects can operate there — because that is where the security actually lives.

## 7. This repository's place

Strictly **L1–L2, descriptive**: characterize the crypto/protocol, publish the
key-layer record (CI), and document the defense design (this `research/` set). It
deliberately stops before L3/L4 — no classifier, no VLM integration, no
behavioral synthesis — because those are the operational-evasion layers.
