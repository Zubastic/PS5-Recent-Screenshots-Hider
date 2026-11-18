# PS5 Recent Screenshots Hider

Standalone resident PS5 payload (FW 11.20, ps5-payload-sdk). Hides the
**"Recent Capture"** action card — the recent screenshots tile on the
home screen — by patching the NPXS40003 (`rnps-control-center`) Hermes
bytecode inside the live SceShellUI process: **six call sites, 2 bytes
each**, every signature unique in the whole HBC. Nothing on disk is
modified; everything is memory-only through PTE-validated kernel dmap
primitives.

Build once, load once from the payload manager (PLK autoload works too)
and it stays in the background for the whole session.

## What it patches

### S1–S5 — the card lifecycle service

The whole card lifecycle is driven by two Hermes functions:

- **F#24683** `updateRecentCaptureAC` @hbc `0x4450A6` — the service's
  AvContentItemAccessor event handler ('added'/'deleted'/'updated'),
- **F#24686** `updateRecentCaptureACForCronos` @hbc `0x4452B7` — the
  cronos content-update listener.

Every event runs one of:

```
card not in strand + contents -> client.addActionCard(SHARE, {...})
card in strand    + contents  -> client.updateActionCard({id,...})
card in strand    + no contents -> client.updateActionCard({id,...})
```

The GetById `string_id` operands of those calls are re-pointed at
`'removeActionCard'` (20458/`0x4FEA`):

```
addActionCard    27189 (0x6A35) -> 20458
updateActionCard 18630 (0x48C6) -> 20458
```

so EVERY update cycle removes the card instead of adding/refreshing it.
`removeActionCard` (F#2969 -> generator F#2971) reads only `param.id`
(extra option fields are ignored), returns `false` for unknown ids (the
`addActionCard` sites pass the SHARE token — a harmless no-op) and its
transaction commit persists the removal (`deleteActionCard` +
`saveActionCardIDs` -> `CC_AC_IDS` / `CC_AC_ID:<id>` in the KV store).
A card persisted by PREVIOUS sessions is therefore removed at the first
update cycle and never comes back: the patch does not have to win the
boot race.

### S6 — the KV restore loader

Sites S1–S5 alone left one hole (verified on console): a
card with **already-active screenshots** stayed visible. The boot-time
restore path (Hermes function #2879) re-loads every persisted card from
AsyncStorage `'CC_AC_IDS'` through **F#5106** (`loadActionCardIDs`
impl @hbc `0x25EA05`) and bypasses the service sites entirely.

F#5106 awaits `AsyncStorage.getItem('CC_AC_IDS')`; a `JmpTrue` at
fn+0x2c picks between the two branches of the result:

- truthy -> fn+0x33 (`GetGlobalObject 'JSON'` -> `'parse'` ->
  `JSON.parse` — the restore path),
- falsy  -> fn+0x2f (`NewObject {}` — the empty branch).

The patch re-points the branch target fn+0x33 -> fn+0x2f (Hermes jump
offsets are relative to the opcode, so the addr8 operand changes
`0x07 -> 0x03`; the register operand `0x01` is rewritten unchanged):

```
patch: 2 bytes 07 01 -> 03 01 @ HBC 0x25EA32  (F#5106 + 0x2d, = sig + 16)
```

Both the truthy and the falsy path now land on the `NewObject`, so the
loader ALWAYS returns `{}` — the state the code handles natively — and
the restore builds an empty store: the persisted card never re-appears.
`loadActionCardIDs` has exactly one caller (the restore #2879, verified
in the disassembly), so the patch is scoped; cards of other types are
re-created by their own services at boot through the unpatched host API
and self-heal.

### Signatures (unique in NPXS40003.hbc)

Verified against the decrypted local dump: exactly 1 hit each.

| site | function | HBC offset | patch | meaning |
|------|----------|-----------:|-------|---------|
| S1 | F#24683 | `0x445199` | `35 6A -> EA 4F` | addActionCard |
| S2 | F#24683 | `0x4451FD` | `C6 48 -> EA 4F` | updateActionCard |
| S3 | F#24683 | `0x445246` | `C6 48 -> EA 4F` | updateActionCard |
| S4 | F#24686 | `0x4453BA` | `35 6A -> EA 4F` | addActionCard |
| S5 | F#24686 | `0x445403` | `C6 48 -> EA 4F` | updateActionCard |
| S6 | F#5106  | `0x25EA22` | `07 01 -> 03 01` | restore-kill (JmpTrue target) |
| S7 | F#24672 | `0x444C44` | `02 29 -> 01 29` | context-gate (JStrictNotEqual reg) |
| S8 | F#24662 | `0x4445E3` | `76 03 -> 77 03` | hasNewContent true -> false |

### S7 — the service context gate

F#24672 skips the card-service update cycle unless the current context
type is `CONTEXT_TYPE_INIT`. The patch rewrites the register operand of
its `JStrictNotEqual` so the cycle runs on EVERY context dispatch — any
home/CC navigation re-runs the funnel and re-removes a resurrected card
within one user action, without waiting for an AvContent event.

### S8 — the hasNewContent producer

F#24662 (`updateAddContent` @`0x4445D6`) is the ONLY producer of
`hasNewContent:true` for this card — the 'new screenshot' event. Its
`LoadConstTrue r3` becomes `LoadConstFalse`. F#2957 (`addActionCard`
impl) **un-persists** a card whose id sits in `persistedRemovedCards`
when the add carries `hasNewContent:true` (the error text says so
explicitly), so without S8 one fresh screenshot would undo the seed
below. F#24663 — the sibling variant — is byte-identical except its
own `LoadConstFalse`, which is why the signature must carry the
`LoadConstTrue` byte.

### The persist-seed window

The resurrection that survived the call-site patches is the host-driven
init push:
the ops channel (F#19218) calls F#2957 **directly**, bypassing the
whole funnel, so no call-site patch can stop it. F#2957 however
REFUSES to re-add a card whose id sits in `persistedRemovedCards.cardIDs`
(throws 'Cannot re-add previously removed action card...', caught by
the ops channel). Production code never sets the persist flag — so the
payload opens a transient 120 s window every ~30 min in which the two
 GetByIds of F#2971 (`removeActionCard` impl, 'removeWhileCCOpen' +
'persist' @`0x22BD2D`, object-param path only) are rewritten as three
`LoadConstTrue` each. The next object-param removal of an existing card
— the S2/S3/S5 update-redirects fire one on every service cycle — then
takes the HARD path with persist=true: the id is pushed into
`persistedRemovedCards.cardIDs` and written to the KV store. The window
closes and the original bytes are restored (seed-and-revert). From then
on the init push throws every time and the card stays dead across
restarts; S8 keeps the entry from being un-persisted.

Safety properties: instruction lengths are preserved (6->6 bytes x2,
all jump targets outside the window), the window sits OUTSIDE the
exception handler, a torn write degrades into a caught throw, and the
write is refused (logged + dumped) unless the window matches the
pristine signature, the applied seed, or the half-written state
(which is repaired). Known limitation: during a window an object-param
removeActionCard of ANY card gets persist forced on it (~7% of wall
time).

Each site is matched by a 18–23 byte signature around the operand; the
operand bytes themselves are wildcarded during the match (the original
value or the already-substituted one both identify the copy), which
makes the payload idempotent. Before writing, the hit is
sanity-checked: the containing copy must have the full Hermes magic
`C6 1F BC 03 C1 03 19 1F` at its base, bytecode version `0x59` at
`+0x08` and `fileLength == 0x5E9150` at `+0x20` — so a false signature
match in some other region cannot receive a write.

### Retired approaches (do NOT re-apply)

- **The retired gate patch** (F#19203, `C1->AC` @`0x3BDD43`): loses the
  boot race
  — the flag is consumed once during bundle initialization, before the
  poller can reach a fresh copy.
- **The retired type-string corruption** (`A->X` @`0x13E9F1`): does not
  touch the card persisted in the KV store (restored from JSON at boot
  and rendered without the live service), and it is the prime suspect
  for the SceShellUI SIGSEGV on WelcomeHub after a game (unknown card
  type + the focus-restore remount of the card list — a proven crash
  pattern for remounted RN components). The payload REPAIRS
  both artifacts in the memory of a live ShellUI (`rc_repair_legacy`).

## How it works

1. Elevate to the COREDUMP authid (`0x4801000000000013`) with full caps
   (a proven pattern).
2. dmap self-test (read + write of our own process) — abort if broken.
3. **JWFAST poller thread (250 ms)** — the fast path:
   - discovers ShellUI itself — one `sysctl(KERN_PROC)`
     name scan per tick (`ki_tdname` @+447), with the allproc/module
     walk as the fallback — so a restarted ShellUI is caught within
     ~300 ms;
   - a kqueue `EVFILT_PROC` watch on `SceSysCore.elf`
     (`NOTE_FORK|NOTE_EXEC|NOTE_TRACK|NOTE_EXIT`, self-healing) kicks
     the poller the moment a fresh ShellUI instance execs;
   - every observed NPXS40003 copy lands at the same slab offsets —
     `hbc_base = 0x4b30 (mod 1MB)`; a second family at `...b30` (the
     container's own `+0xB30` HBC offset) covers a different slab
     layout. One 8-byte window per 1 MB slab of each >= 1 MB, < 1 TB
     region is probed for the FULL Hermes magic `c6 1f bc 03 c1 03
     19 1f`;
   - on a magic hit: triple identification (magic + version +
     fileLength from ONE 0x24-byte read), retired-patch repair, then
     the call-site patches via `kernel_copyin` into the dmap +
     read-back — **before the home screen builds the cards array**;
   - all kernel memops run under `g_kmtx` (kernel copyout/copyin are
     not thread-safe).
4. **Cadence (per-generation model)** — aggressive 250 ms
   probing (SCAN) until every found copy is patched, then **STEADY**:
   a cheap revision of the cached copy every 2 s (the HBC header + the
   sites at the cached base, a handful of dmap reads instead of the
   vmwalk + probe ~13K). A sanity FAIL on a magic hit is a foreign
   Hermes bundle (NPXS40025/40002/... share the magic) — an expected
   probe outcome, NOT a retry cause.
5. **Main loop (monitor + fallback)** — every 20 s it checks the
   poller-liveness counter. Only when the poller has been blind for
   >= 90 s (unexpected heap geometry, or the poller thread failed to
   spawn) does it run the old full scan (`patch_pass`) at the 60 s
   cadence as a safety net.
6. `vm_map` splay-tree walk (root @ `vmspace+0x1d0`; entry `+0x08`
   next, `+0x20` start, `+0x28` end, `+0x64` prot) with the
   kernel-heap pointer heuristic on every pointer — rejects kernel
   `.text` windows (KP safety).
7. procio.h KP guards (report §4): phys address must be non-zero and
   < 512 GB, and `dmap + paddr` must stay inside the kernel dmap
   window (`>> 48 == 0xffff`) before every copyout/copyin.

### Resident behaviour

- The patches are **memory-only** and do not survive a ShellUI restart
  (the HBC copy is rebuilt from the encrypted file on disk). The
  poller owns ShellUI discovery and re-patches every new instance
  within ~300 ms of its decrypt — beating the first render.
- The KV restore kill (S6) makes the hiding **persistent across
  boots**: the removal committed by S1–S5 stays in the KV store, and
  the restore loader can no longer resurrect the card.
- The poller re-checks all sites on every revision: a reverted or
  fresh copy is re-patched automatically (idempotent — an
  already-patched site is detected by its operand and left alone).
- **Full copy tracking**: every confirmed copy of the current ShellUI
  generation is tracked (`tracking copy #N hbc_base=...` in the log)
  and revised every 2 s; once a minute the poller runs the full
  content scan (`PASS: ...` lines) so a fresh copy mapped into the
  same process — an RNPS app reload or bundle re-decrypt, the
  "hides every other time" case — is patched within ~60 s, and the
  S7 context gate re-removes the card on the next context change.
- If the poller thread failed to spawn, the main loop takes over:
  it discovers SceShellUI itself (`FALLBACK: SceShellUI discovered`),
  runs the full scan every 60 s and drives the persist-seed windows —
  a dead poller used to leave the payload inert (discovery was
  poller-owned and nothing else ever set the pid).
- Shows up as `recent-screenshots-hider.elf` in the payload manager
  (`thr_set_name` trick).

## Build

Linux/WSL box with the SDK at `/opt/ps5-payload-sdk`:

```
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
./build.sh
```

Produces `recent-screenshots-hider.elf`.

Before or after changing any signature bytes, run the self-contained
cross-check against the reference bundle:

```
python3 verify_signatures.py            # optional args: <main.c> <NPXS40003.hbc>
```

It parses `RC_S1..S8`(+`_NEW`), `RC_SEED_SIG/NEW/HALF`, `RC_GATE_SIG`
and the `RC_SITES` table straight out of `src/main.c` and verifies every
signature has exactly one hit at its declared offset in the decrypted
`NPXS40003.hbc` (see Files below for where the reference lives).

## Deploy & run

1. Send the ELF to the console and load it (payload loader / PLK
   autoload list).
2. A notification appears on success:
   `RecentScreenshotsHider: recent screenshots hidden`
3. The card disappears on the next home-screen cards refresh
   (PS button / navigation); if the card was already rendered, a
   ShellUI restart also clears it — the payload re-patches after the
   restart by itself.

## Diagnostics

The payload manager does not show stdout, so everything is appended to:

```
/data/homebrew/recent-screenshots-hider.log
```

Every line carries a `[+ss.sss]` monotonic stamp (from payload start)
for correlating SceShellUI crashes with the payload. Example lines:

```
[+  0.000] recent-screenshots-hider 1.0 starting (pid=... fw=0x...)
[+  0.001] elevate: authid ... -> 0x4801000000000013
[+  0.002] self-test OK (dmap read + dmap write)
[+  0.250] JWFAST: SceShellUI found (pid=59)
[+  0.510] JWFAST: 8/8 site(s) patched (hbc_base=0x...) tick=1
[+  1.010] PATCH: F5106 restore-kill @0x... id16 ->0301 (hbc_base=0x...)
[+  1.260] JWFAST: 1 copy(ies) already patched - steady mode (cheap revision every 2s)
[+  3.300] SEED: window OPEN for 120s on 1 copy(ies) (written=1 already=0 fail=0) - obj-param removeActionCard now persists
[+123.456] JWFAST: ticks=... probes=... magic=... patched=1 epoch=... pid=59 state=STEADY
[+123.500] SEED: window closed after 120s - reverted ok=1 skip=0 fail=0
```

`state=STEADY` means every found copy is patched and the poller is
down to the cheap 2 s revision; `state=SCAN` is the aggressive mode.

## KP-safety notes

- Kernel `.text` is **never** read or written: every kernel-space
  pointer obtained during the walks goes through the
  `kernel_is_heap_addr`-style heuristic before dereference, and only
  ShellUI userland pages are scanned.
- All reads are PTE-validated (`proc_read_dmap`); all writes go through
  `kernel_copyin` into the dmap (mdbg write memops are EPERM on 11.20).
- Regions at/above 1 TB are skipped.

## Files

- `src/main.c` — the whole payload (patch table, vm walk, poller,
  daemon loop).
- `src/procio.h` — hardened cross-process dmap IO (no mdbg on the
  foreign path; zombie/pmap-shape/PTE-frame guards).
- `verify_signatures.py` — cross-check of the byte arrays in `main.c`
  against the reference bundle (see Build).
- The reference bundle `NPXS40003.hbc` is **not** committed to the
  repo. Pass its path to `verify_signatures.py` on the command line
  (or place an `NPXS40003.hbc` copy next to the repository).
