# `motionData` — behavioral signal analysis (defensive research)

What hCaptcha's `motionData`/`pdc`/`pem` telemetry *measures* and why it is a
**detection** signal. This is a defender's-eye description of the signal and its
anomaly surface — it is **not** a generator: it does not describe how to
synthesize values that pass. The point is to understand what separates human
interaction from automation at the signal level.

---

## 1. Where it lives

In the decrypted `getcaptcha` request telemetry (§4 of
[`protocol.md`](./protocol.md)) there is a `motionData` JSON
string plus `pdc` and `pem` counter blocks. At the `getcaptcha` moment the
interaction arrays are typically still sparse (the user has only clicked the
checkbox); the rich pointer stream is accumulated **during** the challenge and
submitted at `checkcaptcha`. So `motionData` is a *session-long* behavioral log,
sampled at two points.

## 2. Field groups (observed schema)

| Group | Fields (examples) | What it represents |
|-------|-------------------|--------------------|
| Session timing | `st` (start ts), `v` (schema version) | wall-clock anchors; session age |
| Environment | `sc` (screen: `availWidth/Height`, `colorDepth`, `pixelDepth`, `top/left`…), `or` (orientation), `pel` (widget element HTML) | device/viewport coherence |
| Widget identity | `widgetId`, `widgetList`, `topLevel.inv`, `theme` | which widget, visible/invisible |
| Interaction streams | pointer-move / down / up sequences, touch events, key events (populated during challenge) | the actual biometric evidence |
| Perf counters (`pdc`) | `bfp/bfc/bfa/bsk/bef/big/bpt/vcd/bia`, `gca/gci/gcs/gcad/gcid`, `p` | frame/paint/GC cadence, timing of calls |
| Env meta (`pem`) | `csc`, `csch`, `cscrt`, `cscft` | call-site/context counters |

## 3. The biometric signal (why humans ≠ scripts)

The load-bearing part is the **pointer trajectory + event timing**. Human input
has statistical structure that naive automation lacks:

| Property | Human | Naive automation | Detection angle |
|----------|-------|------------------|-----------------|
| Trajectory | curved, jittery, with sub-movements and corrections | straight lines / teleports / splines too smooth | curvature & jerk distribution; micro-tremor presence |
| Velocity | ballistic profile (accelerate → decelerate, Fitts's-law-like) | constant velocity or instantaneous | velocity/acceleration histograms |
| Timing | variable inter-event intervals, human reaction latencies | fixed deltas, too-regular cadence | inter-arrival entropy; quantization artifacts |
| Dwell / hover | pauses, hesitation before click | click with no approach | pre-click dwell, approach presence |
| Device coherence | motion matches device (mouse vs touch), screen geometry consistent | mismatched (touch events on desktop fp, impossible coords) | cross-signal consistency |
| Sampling | event rate tied to real input device + rAF | synthetic rate, missing rAF coupling | rate fingerprint vs. claimed device |

## 4. Why "fill the fields" isn't enough (for the defender's benefit)

A key defensive property: the signal is **relational**, not a checklist.
Detectors don't ask "is `motionData` present?" — they ask "is this trajectory
*kinematically plausible* for the claimed device, and *coherent* with the
fingerprint, timing counters, and reputation?" That is why:

- Replaying a captured human session fails cross-session (nonces/timestamps,
  per-widget ids, risk context differ).
- Perfectly-smooth synthetic motion is *more* suspicious than none (too clean).
- The `pdc`/`pem` counters cross-check the motion: paint/GC cadence and call
  timing must be consistent with a real rendering browser actually animating the
  widget. Inconsistencies (motion without matching frame cadence) are a tell.

## 5. Defensive takeaways

- **Collect relational features, not presence flags.** Score curvature, jerk,
  velocity-profile shape, inter-event entropy, dwell, and device coherence —
  jointly, not independently.
- **Cross-validate signals.** Motion ↔ fingerprint ↔ timing counters ↔
  reputation must agree; single-signal checks are the easiest to spoof.
- **Weight reputation.** For low-trust contexts, require stronger behavioral
  evidence or escalate challenge difficulty; never accept "fields populated" as
  humanity.
- **Monitor for replay.** Bind sessions to nonces/timestamps/widget ids so a
  captured-and-replayed `motionData` is detectable.

## 6. Scope note

This is **signal analysis for detection**. It intentionally omits any method for
producing passing `motionData` (trajectory synthesis, kinematic modeling to
defeat the classifier, replay crafting) — that would be an evasion tool, which
is out of scope for this research set.
