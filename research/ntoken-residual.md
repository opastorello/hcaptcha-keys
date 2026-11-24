# The n-token key — the open residual (research notes)

The request / response (hsw) and the fingerprint (hsj) keys are fully recovered,
verified, and published hourly. The **n-token key is the one that resists** — and
this note documents, honestly, *why*, with the concrete leads for a future crack.
It matches the pre-existing project note ("the per-build n-token master key is
never materialised as 32 contiguous bytes").

---

## What the n-token is

`window.hsw(jwt)` returns the **n-token** (the PoW + fingerprint blob). Cipher:
**AES-256-CTR**, counter block `iv || be32(counter)`. The token has a stable
2-byte header (`00 05` observed across tokens — a version/type marker, *not* CTR
ciphertext), then the encrypted body, a 16-byte trailing AES block (not a MAC),
and the 12-byte IV. The key is **build-static** (same for every n-token of a
given asset build), so recovering it would decrypt any third party's n-token for
that build.

## Why it resists — confirmed independently

The clean win on hsw was **write-interception**: hook the `u32` virtual-memory
writer, catch the fixslice round-key schedule as it is written, invert, verify.
That does **not** work for the n-token, for compounding reasons:

1. **Scheduled once at init, then cached.** During a gated `window.hsw(jwt)`
   the `u32` writer only re-emits the **request_key** schedule; the n-token key
   schedule is not re-written — it was computed earlier (warmup/instantiation)
   and cached. So the gated capture never contains it.
2. **Capturing from instantiation crashes the module.** Removing the gate and
   capturing every write from the first call needs a large scratch region; on
   the heavy n-token path that region **collides with the WASM's working memory**
   and traps (`unreachable`). A small safe region doesn't reach the schedule.
3. **`hsw(jwt)` as the first call** (small, safe buffer) yields **zero** verified
   schedules in the first thousands of writes — the burst is deeper in the call
   or at instantiation.
4. **Reading the cached schedule doesn't invert.** The reader-based path
   (`recover_ntoken_master_live`) captures a 120-word array from the n-token
   fixslice function, but `inv_bitslice` of it **does not reproduce a standard
   AES-256 master** (self-verification fails → it correctly returns `None` rather
   than a wrong key). This strongly suggests a **non-standard schedule
   representation** (e.g. a whitened/tweaked layout, fixslice64 vs fixslice32, or
   a different word order).
5. **Entry detection is fragile.** The n-token encrypt entry's signature rotates
   per build; `_find_encrypt_entry` was generalised (rank by fixslice-call
   count, signature-agnostic), which makes the n-token helpers *run*, but on
   current builds it does not pinpoint the CTR-loop driver cleanly (it lands on a
   function whose captured buffer is all-zero AES state, not the plaintext).

## The strongest lead (the experiment to finish)

Use **known-keystream as ground truth** — this sidesteps guessing the inversion:

1. Key-free, capture the n-token **plaintext** `pt` (dump the CTR encrypt entry's
   input buffer) and the **token** `ct`/`iv` for the *same* build/call.
2. `keystream = ct XOR pt` → you now hold known `(counter_block_i → keystream_i)`
   pairs under the n-token key (238 of them for a 3.8 KB token).
3. Capture the n-token fixslice **round-key array** (the high-entropy 120 words).
4. Test it **directly**, without inverting to a master:
   `fixslice.aes256_encrypt(captured_schedule, iv||be32(0)) == keystream_0` ?
   - If it matches → the array *is* the schedule; `rk[0:8]`/`rk[8:16]` give the
     master. Done.
   - If not → iterate the representation against the keystream (whitening XOR,
     fixslice64, byte/word order, shift-rows offset) until `aes256_encrypt`
     reproduces the keystream. The keystream makes every hypothesis falsifiable.

This is a bounded but genuine multi-step RE task — it needs one patched module
that simultaneously (a) dumps the plaintext, (b) returns the token, and (c)
captures the fixslice array, all in one pinned-build run, then an offline
representation search against the keystream.

## What works today without the key

- **request / response / hsj keys** — fully recovered + verified + published.
- **Reading your *own* n-tokens** — the key-free plaintext capture path recovers
  the plaintext directly from the encrypt buffer (no key needed) once the entry
  heuristic is tuned to the CTR driver. Decrypting a *third party's* n-token is
  what still needs the key above.

## Status

Parked as the **open residual**. The three protocol keys that matter are solved
and shipping; the n-token key is a separate, bounded RE project with a clear,
falsifiable next experiment (the known-keystream test above).
