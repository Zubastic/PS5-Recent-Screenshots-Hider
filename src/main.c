/*
 * recent-screenshots-hider - standalone resident PS5 payload.
 *
 * Hides the "Recent Capture" action card (recent screenshots) on the
 * PS5 home screen by patching the RNPS control-center bundle
 * (NPXS40003 = rnps-control-center) IN MEMORY, Hermes bytecode.
 *
 * Strategy: CALL-SITE SUBSTITUTION inside the service that owns
 * the card.  F#24683 (updateRecentCaptureAC @hbc 0x4450A6) and F#24686
 * (updateRecentCaptureACForCronos @hbc 0x4452B7) drive the whole card
 * lifecycle - every AvContentItemAccessor event ('added'/'deleted'/
 * 'updated', plus the cronos content-update listener) runs one of:
 *
 *   card not in strand + contents    -> client.addActionCard(SHARE, {...})
 *   card in strand    + contents     -> client.updateActionCard({id,...})
 *   card in strand    + no contents  -> client.updateActionCard({id,...})
 *
 * The GetById string_id operands of those calls are re-pointed at
 * 'removeActionCard' (20458/0x4FEA):
 *   addActionCard    27189 (0x6A35) -> 20458
 *   updateActionCard 18630 (0x48C6) -> 20458
 * so EVERY update cycle removes the card instead of adding/refreshing
 * it.  removeActionCard (F#2969 -> generator F#2971) reads only
 * param.id (extra option fields are ignored), returns false for
 * unknown ids (the addActionCard sites pass the SHARE token - harmless
 * no-op) and its transaction commit persists the removal
 * (deleteActionCard + saveActionCardIDs -> CC_AC_IDS / CC_AC_ID:<id> in
 * the KV store).  A card persisted by PREVIOUS sessions is therefore
 * removed at the first update cycle and never comes back: the patch
 * does not have to win the boot race.
 *
 * Why two early patch approaches were retired (do NOT re-apply):
 *   - the F#19203 gate (C1->AC @0x3BDD43) loses the boot race - the
 *     enableRecentCaptureAC flag is consumed once during bundle
 *     initialization, before the poller can reach the fresh copy;
 *   - the type-string corruption ('A'->'X' @0x13E9F1) does not touch
 *     the card persisted in the KV store, which is restored from JSON
 *     at boot and rendered WITHOUT the live service - the card stayed
 *     visible (verified on console 2026-11-13).  It is also the prime
 *     suspect for the SceShellUI SIGSEGV on WelcomeHub after a game:
 *     an unknown card type combined with the focus-restore remount of
 *     the card list is a proven RN JS executor crash-on-remount
 *     failure mode.
 *
 * Hardening:
 *   - triple bundle identification: full Hermes magic 8 bytes +
 *     bytecode version 0x59 @0x08 + fileLength 0x5E9150 @0x20, all
 *     from ONE 0x24-byte read (rc_hbc_sane);
 *   - the JWFAST probe matches the full 8-byte magic instead of the
 *     4-byte prefix shared with unrelated data;
 *   - rc_repair_legacy restores both retired-patch artifacts in the
 *     memory of a live ShellUI (a ShellUI patched before the payload
 *     swap keeps them running) - check-before-write +
 *     readback-verify, no-ops on a pristine copy, and doubles as
 *     crash mitigation for the type-string suspect.
 *
 * Process handling (proven-parity):
 *   - discovery: a single sysctl(KERN_PROC) scan by name, mib
 *     {1,14,8,0}, variable-length records (ki_structsize stride),
 *     ki_pid @+72, ki_tdname @+447.  One cheap call per tick instead
 *     of the old allproc walk with per-process dynlib probes; the
 *     module walk stays as the fallback if the sysctl path fails;
 *   - restart watch: kqueue EVFILT_PROC on SceSysCore.elf with
 *     NOTE_FORK|NOTE_EXEC|NOTE_TRACK - a fresh SceShellUI instance is
 *     noticed the moment it execs and kicks the poller into aggressive
 *     mode.  The exec'd pid is re-checked by name through the same
 *     sysctl scan (instead of a sceKernelGetAppInfo title_id filter),
 *     and the registration is self-healing (NOTE_EXIT + timeout
 *     re-validate);
 *   - cadence: "patch once per generation" - aggressive 250ms probing
 *     until every copy found is patched (SCAN), then a 2s re-verify
 *     (STEADY); the persistent KV removal keeps the card hidden across
 *     unpatched reload windows.
 *   Unlike the boot-race-flawed reference implementations the pattern
 *   is borrowed from: the patch thread never exits on a lost race,
 *   there are no hard 30s waits, and the full-scan fallback stays.
 *
 * The KV restore hole (why S6 exists):
 *   - sites S1-S5 alone leave one hole (verified on console): a card
 *     with already-active screenshots stays visible - the boot-time
 *     KV restore (#2879 ->
 *     loadActionCardIDs, F#5106) re-loads every persisted card from
 *     AsyncStorage 'CC_AC_IDS' and BYPASSES the service sites S1-S5
 *     entirely.  Site S6 re-points the JmpTrue that picks the
 *     JSON.parse branch of the loader at its empty-object branch
 *     (2 bytes: addr8 0x07 -> 0x03 @0x25EA32, branch target
 *     fn+0x33 -> fn+0x2f), so the loader ALWAYS
 *     returns {} - the state the code handles natively - and the
 *     persisted card never re-appears.  loadActionCardIDs has exactly
 *     one caller (the restore #2879, verified in the disassembly), so
 *     the patch is scoped; cards of other types are re-created by
 *     their own services at boot through the unpatched host API and
 *     self-heal.
 *   - per-site replacement values (rc_site.new2): S1-S5 keep
 *     'removeActionCard' (EA 4F), S6 writes its own 2 bytes.
 *
 * Poller design:
 *   - a sanity FAIL is a foreign Hermes bundle
 *     (NPXS40025/40002/... share the magic) - an expected magic hit,
 *     NOT a retry cause (counting it kept the poller in SCAN forever,
 *     ~32K dmap reads/s wasted).  STEADY is a cheap revision of the
 *     cached copy (header + the sites at the cached base, ~8
 *     reads instead of the vmwalk+probe ~13K), entered only once a
 *     confirmed copy exists; the poller-liveness counter
 *     (g_poll_epoch_magic) increments in the revision, so the main
 *     loop no longer mistakes a healthy STEADY poller for a blind
 *     one.
 *   - log stamps: every plog line carries [+ss.sss] (monotonic from
 *     log open) for correlating SceShellUI crashes with the payload.
 *
 * S7 - auto-refresh on context changes (why it exists):
 *   - with only the event-driven sites, existing screenshots stayed
 *     visible until a manual content event: the card funnel (F#24683
 *     updateRecentCaptureAC) only runs when something invokes the
 *     service.  The service's own onContextChange handler (F#24672)
 *     re-runs the funnel on every strand-manager context dispatch,
 *     but ONLY for CONTEXT_TYPE_INIT - which the host dispatches once
 *     at control-center start, before the payload can patch (the
 *     user-verified reason a manual trigger was needed).  Site
 *     S7 disables that gate: the JStrictNotEqual
 *     'context.type !== CONTEXT_TYPE_INIT' @fn+0x1c is made to
 *     compare its register with ITSELF (register operand 02 -> 01),
 *     so the skip branch is never taken and
 *     updateRecentCaptureAC({hasNewContent:false}) fires on EVERY
 *     context change (app launch/exit = BIG_APP_CHANGED,
 *     SYSTEM_RESUME, connection status, multitask transitions).  Each
 *     run re-queries the media DB and flows through the S1-patched
 *     addActionCard -> removeActionCard, so the card is re-removed
 *     and the removal re-persisted on the first event after boot.
 *
 * Multi-copy tracking + periodic deep rescan (why they exist):
 *   - root cause of "hides every other time": the action-card
 *     manager (addActionCard/removeActionCard/KV persist) exists ONLY
 *     in NPXS40003 - a sweep of all 67 decrypted RNPS bundles found
 *     just three harmless reference kinds elsewhere (getActionCardType
 *     title maps in 40002/40024/40075, a type->component registry in
 *     40036) plus a LinkingAC.open deeplink in the 40024 Create menu
 *     (opens the card as an overlay, never adds it to the home list).
 *     So no second add path exists in JS.  What CAN put an unpatched
 *     copy in front of the user is the poller's coverage:
 *     (a) the RNPS runtime can map a FRESH NPXS40003 copy into the
 *     SAME SceShellUI process (bundle re-decrypt / app reload) with
 *     NO pid change - SCAN never re-runs and STEADY only revised the
 *     one cached base, so the fresh copy ran unpatched indefinitely;
 *     (b) a copy outside the two probe families (0x4b30/0xb30 mod
 *     1MB) is invisible to the probe scan (12/12 observed bases sat
 *     in those families - a guard, not the observed failure).
 *   - the poller now tracks EVERY confirmed copy of the current
 *     generation (RC_MAX_BASES table) and the STEADY pass revises
 *     all of them; a base that stops verifying is dropped, and an
 *     empty table falls back to aggressive SCAN.
 *   - periodic deep rescan: once per RC_DEEP_SCAN_SEC the poller runs
 *     the full content scan (patch_pass - the same pass the main-loop
 *     fallback uses).  It locates copies at ANY offset and patches
 *     the first unpatched one; a fresh copy therefore stays live for
 *     at most ~60s + one context change (the S7 gate re-runs the
 *     funnel on every context dispatch and re-removes the card),
 *     instead of forever.
 *
 * The persist-seed window (killing the "every other time" resurrection
 * for good - the root cause chain, all verified in the bytecode):
 *   - F#2957 (addActionCard impl) refuses to re-add a card whose id
 *     sits in persistedRemovedCards.cardIDs: it throws 'Cannot re-add
 *     previously removed action card. Card was removed with the persist
 *     flag set to true. To re-add the card, please pass
 *     hasNewContent:true' (@fn+0x2f6).  The throw is caught by the ops
 *     channel (F#19218 try/catch) - the card simply never comes back.
 *   - that persist flag is NEVER produced by production code (the only
 *     in-bundle writer passes persist:false), so the protection was
 *     dormant.  The resurrection chain the call-site patches alone
 *     could not close: the host-driven init push (ops channel
 *     F#19218 -> F#2957) re-adds the card after every hard removal,
 *     and commit-on-close (F#13311 -> F#13312) removes it again
 *     without persist - the observed strict alternation.
 *   - SEED: F#2971 (removeActionCard) reads both flags with GetByIds
 *     @fn+0x8d ('removeWhileCCOpen', 24630) and @fn+0x93 ('persist',
 *     19601) - ONLY for object params (the string path jumps to
 *     fn+0x9b past both).  During a transient WINDOW the poller
 *     rewrites those two 6-byte GetByIds as three LoadConstTrue each
 *     (12 bytes @hbc 0x22BD2D, signature unique in the whole HBC), so
 *     the next object-param removeActionCard of an EXISTING card takes
 *     the HARD path with persist=true: the id is pushed into
 *     persistedRemovedCards.cardIDs and savePersistedRemovedCards()
 *     writes it to the KV store.  The window then closes and the
 *     original bytes are restored (seed-and-revert; the seed bytes are
 *     deliberately NOT part of RC_SITES - the STEADY revision would
 *     read them as 'bad' and drop the copy).
 *   - S8 (permanent site) closes the un-persist hole: F#24662
 *     (updateAddContent @0x4445D6) is the ONLY producer of
 *     hasNewContent:true for this card ('new screenshot' event); its
 *     LoadConstTrue r3 @fn+0x0f becomes LoadConstFalse (1 byte,
 *     0x76 -> 0x77).  With S8 in place no funnel path can ever pass
 *     hasNewContent:true to F#2957, so once seeded the persist entry
 *     cannot be undone through the bundle (the cronos funnel F#24686
 *     spreads raw AvContent items that carry no hasNewContent at all).
 *   - lifecycle: window opens RC_SEED_START_DELAY_SEC after a fresh
 *     generation is discovered (the CC init push - the resurrection
 *     moment - happens right after that), stays open
 *     RC_SEED_WINDOW_SEC, then reverts; re-arms every
 *     RC_SEED_RETRY_SEC.  Latching requires the card to EXIST during
 *     a window plus one object-param removal (the S7-forced funnel
 *     cycle on any context change provides both); a missed window is
 *     retried, and even a post-window resurrection is re-removed by
 *     S2/S3 and re-latched by a later window.
 *   - known limits: during a window an object-param removeActionCard
 *     of ANY card gets persist forced on it (a card the user removed
 *     manually in that moment could become un-re-addable until a
 *     hasNewContent:true add - accepted, windows cover ~7% of wall
 *     time).  Uninstall story: without the payload the next new
 *     screenshot passes hasNewContent:true and un-persists the card
 *     by itself.
 *   - opcode note: in THIS bundle's encoding LoadConstTrue = 0x76 and
 *     LoadConstFalse = 0x77 (verified against F#2957 @+0x39f/+0x46a
 *     and F#24662/24663 @+0x0f).  The hermes-dec hbc59.py numbering
 *     (109/110) does NOT match the file bytes - never synthesize
 *     patch bytes from that table.
 *
 * Eight call sites (S1-S3 in F#24683, S4-S5 in F#24686, S6 in the
 * KV-restore loader F#5106, S7 in the service context gate F#24672,
 * S8 in the hasNewContent producer F#24662); every signature is unique
 * in the whole NPXS40003.hbc (verified against the decrypted dump:
 * exactly 1 hit each).  Every patch is 2 bytes: the little-endian
 * string_id operand of the GetById (S1-S5), the JmpTrue target (S6),
 * the register operand of the JStrictNotEqual (S7 - its second byte
 * rewrites the unchanged neighbour, keeping the generic 2-byte apply
 * path), or the LoadConstTrue/False opcode byte (S8 - likewise with
 * its unchanged register neighbour).  On top of the sites, the
 * transient 12-byte persist-seed window (F#2971) runs under poller
 * control; see the persist-seed section above.
 *
 * Robustness notes (why the seed path is written the way it is):
 *   - rc_seed_write writes the full 12 seed bytes in ONE copyin and
 *     recognizes/repairs a torn half-state on the next arm attempt
 *     (log: 'SEED: half-written state repaired') - a short write
 *     would decode as register-clobbering garbage in F#2971's object
 *     path (see the seed comment below);
 *   - unexpected window bytes are dumped to the log, never written
 *     blind;
 *   - without a poller thread the main loop discovers SceShellUI
 *     itself and drives the seed lifecycle (g_shellui_pid is not
 *     poller-owned - otherwise the fallback scan and the seed windows
 *     silently never run);
 *   - a window close that reverted nothing (copies unreadable /
 *     foreign bytes) retries in 60s instead of idling 30 min with the
 *     seed bytes stuck in memory;
 *   - the arm-skip log counts unreadable copies (skip=) separately
 *     from write failures (fail=).
 *
 * How it works (proven stack):
 *   - elevate to the COREDUMP authid (full caps),
 *   - SceShellUI found with one cheap sysctl(KERN_PROC) name
 *     scan per tick (ki_tdname @+447); the allproc walk with
 *     ReactNative-module probes stays as the fallback, and a kqueue
 *     NOTE_EXEC watch on SceSysCore.elf kicks the poller the moment
 *     a fresh SceShellUI instance execs,
 *   - vm_map splay-tree walk (root @vmspace+0x1d0 on FW 11.20; entry
 *     +0x08 next, +0x10 left, +0x18 right, +0x20 start, +0x28 end,
 *     +0x64 prot) with the kernel-heap pointer heuristic on every
 *     pointer (rejects kernel .text windows - KP safety),
 *   - the JWFAST poller probes one 8-byte window per 1MB slab for the
 *     full Hermes magic (C6 1F BC 03 C1 03 19 1F) and, once the triple
 *     identification confirms an NPXS40003 copy, repairs any retired-patch
 *     leftovers and applies all call-site patches via kernel_copyin
 *     into the dmap, reading them back for verification,
 *   - the main loop full scan is the fallback when the poller is blind;
 *     it locates the copy by any site signature and then applies all
 *     sites at their fixed HBC offsets,
 *   - resident: re-patches automatically after every ShellUI restart
 *     (the bytecode copy is rebuilt from the encrypted file on disk,
 *     so the patch is memory-only and does not survive restarts),
 *     idempotent (an already-patched site carries the new id16 and is
 *     left alone).
 *
 * Diagnostics: the payload manager does not show stdout, so the log is
 * appended to /data/homebrew/recent-screenshots-hider.log.
 */

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <time.h>
#include <unistd.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>

#include "procio.h"

/* the SDK's errno.h expands errno to (*__error()) but hides the
 * __error() declaration under __STRICT_ANSI__ (-std=c11); declare it
 * explicitly so the payload builds with any -std setting */
int *__error(void);

#ifndef RSH_VERSION
#define RSH_VERSION "dev"
#endif

#define PAYLOAD_NAME "recent-screenshots-hider.elf"
#define LOG_PATH "/data/homebrew/recent-screenshots-hider.log"

/* poll cadence: the JWFAST poller is aggressive (250ms ticks) in SCAN
 * state - fresh ShellUI generation / unpatched copies - and drops to a
 * 2s re-verify in STEADY state once every found copy is patched
 * (the per-generation model).  The main loop only monitors and
 * runs the full scan as a fallback when the poller is blind
 * (unexpected heap geometry, or the poller thread failed to spawn) */
#define POLL_PROBE_SEC 20   /* monitor tick while idle / not yet patched */
#define POLL_RECHECK_SEC 60 /* fallback retry after a pass that found nothing */
#define FALLBACK_GRACE_SEC 90 /* fallback only after this much uptime   */
#define POLL_TICK_US (250 * 1000) /* JWFAST prober tick                  */
#define RC_REVERIFY_SEC 2  /* STEADY-state re-verify cadence           */
#define RC_DEEP_SCAN_SEC 60 /* STEADY: periodic full content rescan
                             * - catches copies the probe families and
                             * the cached-base revision cannot see    */

/* ------------------------------------------------------------------ */
/* the P40003 patch sites                                              */

static void plog(const char *fmt, ...);

/* little-endian string_id 20458 = 'removeActionCard' (method of the AC
 * strand client object, F#2969) - the substitution target.
 * NOTE: 0x4FEA, NOT 0x4FCA (20426 = 'saveOrderAndVisibilityReducer') -
 * verified by disassembling a patched copy of the bundle. */
static const uint8_t RC_NEW2[2] = {0xEA, 0x4F};

/* original id16 operands, for reference/logging:
 *   27189 = 0x6A35 'addActionCard'    -> bytes 35 6A
 *   18630 = 0x48C6 'updateActionCard' -> bytes C6 48
 * (both are part of the signatures below) */

struct rc_site {
  const char *name;
  const uint8_t *sig;   /* unique in the whole HBC (1 hit, verified)   */
  uint32_t sig_len;
  uint32_t op_off;      /* offset of the 2-byte string_id inside sig   */
  uint64_t sig_hbc_off; /* sig offset inside the NPXS40003.hbc file    */
  const uint8_t *new2;  /* 2-byte replacement written at op_off        */
};

/* S1/S2/S3 - F#24683 (updateRecentCaptureAC @0x4450A6):
 *   S1 @fn+0x0fc GetById r11,r12 client.'addActionCard'   (id16 @+0x100)
 *   S2 @fn+0x160 GetById r8, r9  client.'updateActionCard' (id16 @+0x164)
 *   S3 @fn+0x1a9 GetById r7, r8  client.'updateActionCard' (id16 @+0x1ad)
 * S4/S5 - F#24686 (updateRecentCaptureACForCronos @0x4452B7):
 *   S4 @fn+0x10f GetById r7, r4  client.'addActionCard'   (id16 @+0x113)
 *   S5 @fn+0x159 GetById r3, r4  client.'updateActionCard' (id16 @+0x15d)
 * Preceding context: LoadFromEnvironment env[0] + GetByIdShort 'client'
 * (the trailing 0x64 = id8 of 'client'); S4/S5 carry more of their
 * generator body for uniqueness. */
static const uint8_t RC_S1[19] = {
    0x2E, 0x09, 0x06, 0x00, 0x34, 0x0C, 0x09, 0x04, 0x64, 0x35,
    0x0B, 0x0C, 0x0D, 0x35, 0x6A, 0x2E, 0x08, 0x08, 0x0B};
static const uint8_t RC_S2[19] = {
    0x2E, 0x07, 0x06, 0x00, 0x34, 0x09, 0x07, 0x04, 0x64, 0x35,
    0x08, 0x09, 0x0E, 0xC6, 0x48, 0x34, 0x0D, 0x04, 0x0F};
static const uint8_t RC_S3[19] = {
    0x2E, 0x07, 0x06, 0x00, 0x34, 0x08, 0x07, 0x04, 0x64, 0x35,
    0x07, 0x08, 0x0E, 0xC6, 0x48, 0x34, 0x0A, 0x04, 0x0F};
static const uint8_t RC_S4[22] = {
    0x2E, 0x04, 0x04, 0x00, 0x34, 0x04, 0x04, 0x01, 0x64, 0x8E,
    0x4D, 0x05, 0x35, 0x07, 0x04, 0x0D, 0x35, 0x6A, 0x2E, 0x03,
    0x03, 0x0B};
static const uint8_t RC_S5[23] = {
    0x94, 0x04, 0x5A, 0x03, 0x85, 0x03, 0x06, 0x90, 0x30, 0x06,
    0x86, 0x5A, 0x03, 0x35, 0x03, 0x04, 0x0E, 0xC6, 0x48, 0x34,
    0x06, 0x05, 0x0F};

/* S6 - F#5106 (loadActionCardIDs impl @0x25EA05): the boot-time KV
 * restore reads AsyncStorage 'CC_AC_IDS' and, for a non-empty value,
 * re-loads every persisted card - INCLUDING the recent-capture card
 * removed by our patches in PREVIOUS sessions (the restore #2879
 * bypasses the service sites S1-S5 entirely - that is why a card with
 * already-active screenshots stayed visible).  The site
 * is the JmpTrue @fn+0x2c that picks between the two branches of the
 * awaited getItem result: truthy -> fn+0x33 (GetGlobalObject 'JSON' ->
 * 'parse' -> JSON.parse), falsy -> fall-through fn+0x2f (NewObject {}
 * - the empty branch).  Re-pointing the branch target fn+0x33 ->
 * fn+0x2f makes the
 * loader ALWAYS return {} - the state the code handles natively - so
 * the restore builds an empty store and the persisted card never
 * re-appears.  loadActionCardIDs has exactly one caller (the restore
 * #2879, verified in the disassembly), so the patch is scoped; cards
 * of other types are re-created by their own services at boot through
 * the unpatched host API and self-heal.
 * Signature (18 bytes, unique in the whole HBC - exactly 1 hit
 * @0x25EA22): Call2 getItem -> SaveGenerator -> Ret -> ResumeGenerator
 * -> JmpTrue @fn+0x48 -> JmpTrue @fn+0x33 (the branch pick itself).
 * Patch: 2 bytes {0x03, 0x01} - the JmpTrue addr8 (0x07 -> 0x03; the
 * branch target moves fn+0x33 -> fn+0x2f, since Hermes jump offsets
 * are relative to the opcode: 0x2c+7=0x33 in the listing), the
 * register operand 0x01 is rewritten unchanged.  Both the truthy and
 * the falsy path now land on the NewObject, so the loader ALWAYS
 * returns {}. */
static const uint8_t RC_S6[18] = {
    0x51, 0x01, 0x02, 0x03, 0x01, 0x94, 0x04, 0x5A, 0x01, 0x85,
    0x01, 0x02, 0x8E, 0x1F, 0x02, 0x8E, 0x07, 0x01};
static const uint8_t RC_S6_NEW[2] = {0x03, 0x01};

/* S7 - F#24672 (the service's onContextChange handler @0x444C32):
 * the RecentCaptureService re-runs its card funnel from its context
 * handler, but only when context.type === CONTEXT_TYPE_INIT - which
 * the host dispatches once at strand-manager init, BEFORE the payload
 * can patch (the user-verified reason a card with old screenshots
 * stayed visible until a manual content event).  The gate is the
 * 4-byte JStrictNotEqual @fn+0x1c (HBC 0x444C4E): BC 1F 01 02 =
 *   JStrictNotEqual Addr8:0x1f, Reg1, Reg2   (target fn+0x3b)
 * i.e. "if (context.type !== CONTEXT_TYPE_INIT) skip the update".
 * Patch: register operand byte 3 (02 -> 01) makes the instruction
 * compare Reg1 WITH Reg1 - always strict-equal, so the skip branch is
 * never taken and updateRecentCaptureAC({hasNewContent:false}) runs
 * for EVERY context change (BIG_APP_CHANGED on app launch/exit,
 * SYSTEM_RESUME, connection status, multitask transitions).  Each run
 * re-queries the media DB and flows through the S1-patched
 * addActionCard -> removeActionCard, so the card is removed (and the
 * removal re-persisted to KV) on the first event after boot.
 * Safety: the update block never touches the context object; the
 * generator resumption guard (StartGenerator/ResumeGenerator/
 * JmpTrue @fn+0x04) is untouched; the funnel is idempotent and its
 * exceptions are swallowed by the strand-manager's
 * raiseContextChange try/catch (AppError.sendErrorNormal), so firing
 * it for unrelated context types cannot crash the shell.
 * Signature (18 bytes, unique in the whole HBC - exactly 1 hit
 * @0x444C44): LoadFromEnvironment slot10 (the CONTEXT_TYPE enum
 * object) -> GetById id16 0x5B54 ('CONTEXT_TYPE_INIT') ->
 * the JStrictNotEqual itself -> the GetEnvironment of the update
 * block.  Patch: 2 bytes {0x01, 0x29} @sig+13 - the register operand
 * 02 -> 01 plus the UNCHANGED neighbour byte 0x29 (kept so the
 * generic 2-byte apply/verify path works as-is). */
static const uint8_t RC_S7[18] = {
    0x2E, 0x01, 0x01, 0x0A, 0x35, 0x01, 0x01, 0x02, 0x54, 0x5B,
    0xBC, 0x1F, 0x01, 0x02, 0x29, 0x01, 0x01, 0x2E};
static const uint8_t RC_S7_NEW[2] = {0x01, 0x29};

/* S8 - F#24662 (updateAddContent @0x4445D6, 29 bytes): the 'new
 * screenshot' handler - the ONLY producer of hasNewContent:true for
 * the Recent Capture card:
 *   updateRecentCaptureAC.call(svc, {hasNewContent: true})
 * The funnel (F#24683 @+0x173/+0x184) copies that flag into the card
 * descriptor, and F#2957 (addActionCard) UN-persists a card whose id
 * sits in persistedRemovedCards whenever the add carries
 * hasNewContent:true (fn+0x2df: 'To re-add the card, please pass
 * hasNewContent:true') - i.e. every new screenshot would erase the
 * persist-seed.  F#24663 (the 'other update' variant) is
 * byte-identical except its LoadConstFalse, so the signature MUST
 * carry the LoadConstTrue byte itself.
 * Bytecode (real file encoding - LoadConstTrue = 0x76, LoadConstFalse
 * = 0x77, verified against F#2957 @+0x39f/+0x46a):
 *   fn+0x0d  03 00              NewObject r0
 *   fn+0x0f  76 03              LoadConstTrue r3     <- the patch
 *   fn+0x11  3e 00 03 92 4c     PutNewOwnById r0,r3,'hasNewContent'
 *   fn+0x16  51 00 01 02 00     Call2 r0,r1,r2,r0
 * Signature (12 bytes, unique in the whole HBC - exactly 1 hit
 * @0x4445E3): NewObject -> LoadConstTrue -> PutNewOwnById id16 0x4C92
 * ('hasNewContent') -> Call2 head.  Patch: 2 bytes {0x77, 0x03} @+2 -
 * LoadConstFalse r3; the register neighbour 0x03 is rewritten
 * unchanged, keeping the generic 2-byte apply path.  After the patch
 * the funnel only ever sees hasNewContent:false (the same value S7's
 * forced context-cycle passes), so a seeded persist entry can never
 * be undone from inside the bundle. */
static const uint8_t RC_S8[12] = {
    0x03, 0x00, 0x76, 0x03, 0x3E, 0x00, 0x03, 0x92, 0x4C, 0x51,
    0x00, 0x01};
static const uint8_t RC_S8_NEW[2] = {0x77, 0x03};

static const struct rc_site RC_SITES[] = {
    {"F24683 addActionCard", RC_S1, sizeof(RC_S1), 13, 0x445199ull,
     RC_NEW2},
    {"F24683 updateAction#1", RC_S2, sizeof(RC_S2), 13, 0x4451FDull,
     RC_NEW2},
    {"F24683 updateAction#2", RC_S3, sizeof(RC_S3), 13, 0x445246ull,
     RC_NEW2},
    {"F24686 addActionCard", RC_S4, sizeof(RC_S4), 16, 0x4453BAull,
     RC_NEW2},
    {"F24686 updateActionCard", RC_S5, sizeof(RC_S5), 17, 0x445403ull,
     RC_NEW2},
    {"F5106 restore-kill", RC_S6, sizeof(RC_S6), 16, 0x25EA22ull,
     RC_S6_NEW},
    {"F24672 context-gate", RC_S7, sizeof(RC_S7), 13, 0x444C44ull,
     RC_S7_NEW},
    {"F24662 newContent-false", RC_S8, sizeof(RC_S8), 2, 0x4445E3ull,
     RC_S8_NEW},
};
#define RC_SITE_N (sizeof(RC_SITES) / sizeof(RC_SITES[0]))
#define RC_SIG_MAX 23          /* longest site signature             */
#define RC_HBC_FILELEN 0x5E9150ULL /* NPXS40003 Hermes fileLength    */

/* triple bundle identification (hardened practice): full Hermes
 * magic 8 bytes + bytecode version @0x08 + fileLength @0x20 - all of
 * it read with ONE 0x24-byte proc_read_dmap in rc_hbc_sane */
static const uint8_t RC_HBC_MAGIC8[8] = {0xc6, 0x1f, 0xbc, 0x03,
                                         0xc1, 0x03, 0x19, 0x1f};
#define RC_HBC_VERSION 0x59u /* Hermes bytecode version @0x08 (11.20) */

/* retired second site, DISABLED: corrupting the shared
 * 'PlatformEngagementCardRecentCapture' string does not touch the card
 * persisted in the KV store (restored from JSON at boot and rendered
 * without the live service), so the card stayed visible - AND it is
 * the prime suspect for the SceShellUI SIGSEGV on WelcomeHub after a
 * game: an unknown card type + the focus-restore remount of the card
 * list is a proven RN JS executor crash-on-remount failure mode.
 * Never re-apply;
 * repair instead (rc_repair_legacy below). */
#define RSH_TYPE_STRING_PATCH 0
#define RC_TYPE_OFF 0x13E9F1ULL /* 'ActionCardRecentCapture' in the
                                 * string storage (8-byte sanity head) */

/* the retired gate patch: the F#19203 gate byte 'C1'->'AC'
 * @0x3BDD43 - the string lookup 0x24C1 ('enableRecentCaptureAC') is
 * re-pointed at 0x24AC ('actionCardDebug', always false).  Dead as a
 * patch (loses the boot race), but a ShellUI process patched by the
 * retired patches BEFORE the payload swap still carries both
 * artifacts in memory - rc_repair_legacy restores them (repair
 * previous patch forms in memory). */
#define RC_GATE_OFF 0x3BDD3BULL /* retired gate signature offset @HBC    */
static const uint8_t RC_GATE_SIG[31] = {
    0x35, 0x03, 0x05, 0x02, 0x8B, 0x87, 0x71, 0x00, 0xC1, 0x24, 0x51,
    0x00, 0x03, 0x05, 0x00, 0x90, 0x0C, 0x00, 0x2E, 0x03, 0x01, 0x10,
    0x34, 0x00, 0x03, 0x01, 0x73, 0x42, 0x04, 0x00, 0x0D};
#define RC_GATE_OP 8         /* position of the gate byte in the sig   */
#define RC_GATE_PRISTINE 0xC1
#define RC_GATE_LEGACY 0xAC  /* what the retired patch wrote         */

#if RSH_TYPE_STRING_PATCH
static void rc_kill_type_string(pid_t pid, uint64_t hbc_base) {
  uint8_t chk[8];
  if (proc_read_dmap(pid, hbc_base + RC_TYPE_OFF, chk, sizeof(chk)) != 0 ||
      memcmp(chk, "ActionCa", sizeof(chk)) != 0)
    return; /* not our copy or already corrupted */
  const uint8_t xb = 'X';
  if (proc_write_dmap(pid, hbc_base + RC_TYPE_OFF, &xb, 1) == 0)
    plog("JWFAST: type string corrupted @0x%012llx\n",
         (unsigned long long)(hbc_base + RC_TYPE_OFF));
}
#endif

/* Restore the two retired-patch artifacts in the memory of a live
 * ShellUI.
 * Both repairs are check-before-write + readback-verify and no-ops on
 * a pristine copy, so they are safe to run on every confirmed HBC
 * copy.  The type-string repair doubles as crash mitigation
 * (hypothesis #1 for the WelcomeHub SIGSEGV). */
static void rc_repair_legacy(pid_t pid, uint64_t hbc_base,
                             uint64_t region_end) {
  uint8_t win[sizeof(RC_GATE_SIG)], t[8], chk;
  uint64_t va;

  /* gate byte 0xAC -> 0xC1, guarded by the full 31-byte context */
  va = hbc_base + RC_GATE_OFF;
  if (va + sizeof(win) <= region_end &&
      proc_read_dmap(pid, va, win, sizeof(win)) == 0 &&
      memcmp(win, RC_GATE_SIG, RC_GATE_OP) == 0 &&
      memcmp(win + RC_GATE_OP + 1, RC_GATE_SIG + RC_GATE_OP + 1,
             sizeof(win) - RC_GATE_OP - 1) == 0 &&
      win[RC_GATE_OP] == RC_GATE_LEGACY) {
    const uint8_t b = RC_GATE_PRISTINE;
    if (proc_write_dmap(pid, va + RC_GATE_OP, &b, 1) == 0 &&
        proc_read_dmap(pid, va + RC_GATE_OP, &chk, 1) == 0 &&
        chk == RC_GATE_PRISTINE)
      plog("REPAIR: legacy gate byte restored (AC->C1) @0x%012llx\n",
           (unsigned long long)(va + RC_GATE_OP));
  }

  /* card type string "XctionCa..." -> "ActionCa..." (crash suspect) */
  va = hbc_base + RC_TYPE_OFF;
  if (va + sizeof(t) <= region_end &&
      proc_read_dmap(pid, va, t, sizeof(t)) == 0 &&
      memcmp(t, "XctionCa", sizeof(t)) == 0) {
    const uint8_t a = 'A';
    if (proc_write_dmap(pid, va, &a, 1) == 0 &&
        proc_read_dmap(pid, va, &chk, 1) == 0 && chk == 'A')
      plog("REPAIR: legacy card type restored (X->A) @0x%012llx\n",
           (unsigned long long)va);
  }
}

/* ------------------------------------------------------------------ */
/* persist-seed: transient window that turns ONE                        */
/* object-param removeActionCard of an existing card into a HARD        */
/* removal with persist=true, which writes the card id into             */
/* persistedRemovedCards.cardIDs (KV store).  From then on F#2957       */
/* refuses to re-add the card (throw, caught by the ops channel) -      */
/* the "every other time" resurrection dies for good.                   */
/*                                                                      */
/* F#2971 (removeActionCard impl @0x22BCA0) reads both flags with       */
/* GetByIds ONLY on the object-param path (the string path jumps to     */
/* fn+0x9b past them, so the SHARE-token no-ops are untouched):         */
/*   fn+0x8d  35 03 13 04 36 60   GetById r3,r19,u8=4,id16 24630        */
/*                                ('removeWhileCCOpen')   @0x22BD2D     */
/*   fn+0x93  35 08 13 05 91 4c   GetById r8,r19,u8=5,id16 19601        */
/*                                ('persist')             @0x22BD33     */
/* Replacement: three LoadConstTrue each (6 bytes -> 6 bytes, only the
 * dst registers r3/r8 are touched - instruction boundaries, the Jmp
 * @fn+0x99 and every jump target (0x72/0x9b/0x9f/0xcd/...) stay
 * intact; the pair sits OUTSIDE the exception handler [0xe9..0x491]).
 * With both flags forced true: the 'persist && !removeWhileCCOpen'
 * throw cannot fire, the SOFT branch (isActivated &&
 * !removeWhileCCOpen) is skipped, the persist gate takes the
 * (persist ? removeWhileCCOpen : persist) = true arm and the id is
 * pushed + saved.  A torn 12-byte write (Hermes reading between our
 * two GetById rewrites) degrades to persist=true alone -> the
 * caught 'persist flag is only available...' throw - safe.
 * The seed bytes are deliberately NOT in RC_SITES: the STEADY
 * revision would read them as 'bad' and drop the copy.
 * Lifecycle lives in rc_seed_tick (poller thread, g_kmtx held).        */

#define RC_SEED_WINDOW_SEC 120 /* window the seed bytes stay applied    */
#define RC_SEED_RETRY_SEC                                          \
  1800                     /* re-arm cadence after a window closed  \
                            * (a window covers ~7% of wall time -   \
                            * the forced-persist exposure for other \
                            * cards' manual removals stays small)   */
#define RC_SEED_START_DELAY_SEC 3 /* first window after a fresh          \
                                   * generation: the CC init push (the \
                                   * resurrection moment) lands right \
                                   * after the copy is discovered      */
#define RC_SEED_NOTYET_SEC 2     /* no copy known yet: re-check soon    */

/* 12-byte signature: the two GetByIds back to back (unique in the
 * whole HBC - exactly 1 hit @0x22BD2D) */
static const uint8_t RC_SEED_SIG[12] = {
    0x35, 0x03, 0x13, 0x04, 0x36, 0x60, 0x35, 0x08, 0x13, 0x05,
    0x91, 0x4C};
/* replacement: 3x LoadConstTrue r3 + 3x LoadConstTrue r8
 * (real opcode 0x76 - see the S8 note; NOT the 0x6D of hbc59.py) */
static const uint8_t RC_SEED_NEW[12] = {
    0x76, 0x03, 0x76, 0x03, 0x76, 0x03, 0x76, 0x08, 0x76, 0x08,
    0x76, 0x08};
#define RC_SEED_HBC_OFF 0x22BD2Dull /* F#2971 fn+0x8d               */

static time_t g_seed_deadline; /* window open until this time; 0 = shut */
static time_t g_seed_next;     /* earliest next arm attempt             */

/* Write the 12 seed bytes on one copy.  arm=true applies the seed,
 * arm=false restores the original GetByIds.  Idempotent: already in
 * the wanted state = success without IO.  Bytes that are neither the
 * signature, our replacement nor the torn half-state are
 * foreign/garbage - never written (dumped to the log instead).
 * Returns: 2 = written+verified, 1 = already in wanted state,
 * 0 = copy unreadable/gone, -1 = unexpected bytes (skipped),
 * -2 = write/verify failure.  g_kmtx must be held.
 *
 * Hazard note (why the half-state is recognized): a SHORT write here
 * - fewer than all 12 bytes - would leave F#2971's object path with
 * the seed head + a pristine `13 05 91 4c` tail that decodes as
 * `LessEq r5, r145, r76`, clobbering the card-id register (r5) with
 * stack garbage.  Every S2/S3/S5 update-redirect (object param) then
 * becomes a silent no-op and the card stops being removed.  The
 * half-state (RC_SEED_HALF below) is therefore recognized and
 * repaired by a full write on the next arm attempt. */
static const uint8_t RC_SEED_HALF[12] = {
    0x76, 0x03, 0x76, 0x03, 0x76, 0x03, 0x76, 0x08, /* seed head  */
    0x13, 0x05, 0x91, 0x4C};                        /* pristine tail */

static int rc_seed_write(pid_t pid, uint64_t hbc_base, bool arm) {
  const uint8_t *from = arm ? RC_SEED_SIG : RC_SEED_NEW;
  const uint8_t *to = arm ? RC_SEED_NEW : RC_SEED_SIG;
  uint64_t va = hbc_base + RC_SEED_HBC_OFF;
  uint8_t win[sizeof(RC_SEED_SIG)];

  if (proc_read_dmap(pid, va, win, sizeof(win)) != 0)
    return 0; /* copy unmapped / unreadable */
  if (memcmp(win, to, sizeof(win)) == 0)
    return 1; /* already in the wanted state */
  bool repair = memcmp(win, RC_SEED_HALF, sizeof(win)) == 0;
  if (!repair && memcmp(win, from, sizeof(win)) != 0) {
    /* foreign bytes: never write blind - dump them for the log */
    plog("SEED: unexpected bytes @0x%012llx: %02x %02x %02x %02x %02x "
         "%02x %02x %02x %02x %02x %02x %02x\n",
         (unsigned long long)va, win[0], win[1], win[2], win[3], win[4],
         win[5], win[6], win[7], win[8], win[9], win[10], win[11]);
    return -1; /* neither pristine nor ours: do not write blind */
  }
  if (proc_write_dmap(pid, va, to, sizeof(RC_SEED_NEW)) != 0 ||
      proc_read_dmap(pid, va, win, sizeof(win)) != 0 ||
      memcmp(win, to, sizeof(win)) != 0)
    return -2;
  if (repair)
    plog("SEED: half-written state repaired @0x%012llx\n",
         (unsigned long long)va);
  return 2;
}

/* ------------------------------------------------------------------ */
/* JWFAST: patch-on-decrypt prober (background thread)                  */
/*                                                                      */
/* The full scan (patch_pass) takes minutes and cannot beat the first   */
/* render: a fresh home screen decrypts the bundle into a NEW heap      */
/* container and runs the service within ~1-2s.  Every observed         */
/* NPXS40003 copy lands at the same slab offsets - hbc_base = 0x4b30    */
/* (mod 1MB), the container itself stores the HBC at +0xB30 (trophy     */
/* apps: +0xB20) - so the poller probes one 8-byte window per 1MB slab  */
/* of each mapped region for the FULL Hermes magic (c6 1f bc 03 c1 03   */
/* 19 1f - the 4-byte prefix alone matches unrelated data) and, after   */
/* the triple identification, repairs legacy leftovers and applies     */
/* the call-site substitutions immediately on a fresh copy.  A second   */
/* probe family at ...b30 (mod 1MB) covers a different slab layout,     */
/* should the heap arena geometry ever change.                          */
/* Boot-race note: unlike the retired gate patches, the substitution    */
/* does not have to precede the first service run - a card added before */
/* the patch lands is removed (and the removal persisted) by the first  */
/* update cycle AFTER the patch.                                        */
/* Kernel memops are not thread-safe: the poller and the main loop      */
/* serialize every kernel_copyout/copyin user with g_kmtx.              */

#define RC_MAGIC8 0x1f1903c103bc1fc6ull /* full Hermes magic "c6 1f bc
                                          * 03 c1 03 19 1f", LE u64    */
#define RC_SLAB_N 2            /* probe families per 1MB slab          */

static const uint64_t rc_slab_off[RC_SLAB_N] = {0x4b30ull, 0xb30ull};

/* kernel memops are not thread-safe: everything below runs with the
 * mutex held */
static pthread_mutex_t g_kmtx = PTHREAD_MUTEX_INITIALIZER;

static volatile pid_t g_shellui_pid; /* maintained by the poller thread */
static volatile bool g_run = true;   /* payload runs forever            */
static volatile uint64_t g_poll_ticks, g_poll_probes, g_poll_magic,
    g_poll_epoch_magic; /* revision passes for the CURRENT ShellUI pid:
                         * the main-loop fallback reads this as the
                         * poller-liveness signal */
/* every triple-confirmed HBC copy of the CURRENT ShellUI generation.
 * The RNPS runtime can map a fresh NPXS40003 copy into the
 * SAME process (bundle re-decrypt / app reload) without a pid change -
 * a single cached base kept revising the old copy while the fresh one
 * ran unpatched (the "hides every other time" suspect). */
#define RC_MAX_BASES 8
static uint64_t g_poll_bases[RC_MAX_BASES];
static int g_poll_nbases;
static bool g_notified;

/* ------------------------------------------------------------------ */
/* log + notification                                                  */

static FILE *g_log;
static struct timespec g_log_t0; /* log-open instant: every plog line
                                  * carries a [+ss.sss] stamp (mono-
                                  * tonic), so SceShellUI crashes can
                                  * be correlated with the payload */

static void plog(const char *fmt, ...) {
  char line[768], stamped[800];
  va_list ap;
  struct timespec ts;

  if (!g_log)
    return;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  va_start(ap, fmt);
  vsnprintf(line, sizeof(line), fmt, ap);
  va_end(ap);
  /* one fputs: the stamp and the line leave in a single write() */
  snprintf(stamped, sizeof(stamped), "[+%7.3f] %s",
           (double)(ts.tv_sec - g_log_t0.tv_sec) +
               (double)(ts.tv_nsec - g_log_t0.tv_nsec) / 1e9,
           line);
  fputs(stamped, g_log);
  fflush(g_log);
}

struct NotifyRequest {
  char useless[45];
  char message[3075];
};

int sceKernelSendNotificationRequest(int device, struct NotifyRequest *req,
                                     size_t size, int unused);

static void notify(const char *msg) {
  struct NotifyRequest req;
  memset(&req, 0, sizeof(req));
  snprintf(req.message, sizeof(req.message), "%s", msg);
  sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

/* ------------------------------------------------------------------ */
/* elevation (proven pattern)                                          */

static const uint8_t k_full_caps[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff};

static const uint64_t kAuthIds[] = {0x4801000000000013ULL,
                                    0x4800000000010003ULL};

static uint64_t elevate(uint64_t *saved_authid) {
  *saved_authid = kernel_get_ucred_authid(getpid());
  for (size_t i = 0; i < sizeof(kAuthIds) / sizeof(kAuthIds[0]); i++) {
    if (kernel_set_ucred_authid(getpid(), kAuthIds[i]) != 0) {
      plog("elevate: authid 0x%016" PRIx64 " failed (errno=%d)", kAuthIds[i],
           errno);
      continue;
    }
    if (kernel_set_ucred_caps(getpid(), k_full_caps) != 0) {
      plog("elevate: caps failed (errno=%d)", errno);
      kernel_set_ucred_authid(getpid(), *saved_authid);
      continue;
    }
    plog("elevate: authid 0x%016" PRIx64 " -> 0x%016" PRIx64, *saved_authid,
         kAuthIds[i]);
    return kAuthIds[i];
  }
  return 0;
}

/* Self-test both directions of cross-process IO on our own process.
 * Reads and writes both go through the dmap walk (procio.h) - the
 * whole point of this payload is a 1-byte foreign-process write. */
static uint64_t g_selftest_var;

static int self_test(void) {
  const uint64_t wval = 0xA5A5A5A512345678ULL;
  uint64_t rval = 0;

  if (proc_write_dmap(getpid(), (uintptr_t)&g_selftest_var, &wval,
                      sizeof(wval)) != 0) {
    plog("self-test WRITE FAIL errno=%d (%s)", errno, strerror(errno));
    return -1;
  }
  if (proc_read_dmap(getpid(), (uintptr_t)&g_selftest_var, &rval,
                     sizeof(rval)) != 0) {
    plog("self-test READ FAIL errno=%d (%s)", errno, strerror(errno));
    return -1;
  }
  if (rval != wval) {
    plog("self-test data mismatch (got 0x%016" PRIx64 ")", rval);
    return -1;
  }
  plog("self-test OK (dmap read + dmap write)");
  return 0;
}

/* ------------------------------------------------------------------ */
/* Process enumeration (allproc walk, proven probe pattern)            */

#define PROC_OFF_NEXT 0x00
#define PROC_OFF_PID 0xBC

static size_t load_procs(pid_t *out_pids, size_t max) {
  size_t n = 0;
  unsigned long kaddr = 0;

  if (kernel_copyout(KERNEL_ADDRESS_ALLPROC, &kaddr, sizeof(kaddr)) != 0) {
    plog("allproc head read failed errno=%d (%s)", errno, strerror(errno));
    return 0;
  }
  for (size_t guard = 0; kaddr && n < max && guard < 1024; guard++) {
    unsigned int pid = 0;
    if (kernel_copyout(kaddr + PROC_OFF_PID, &pid, sizeof(pid)) == 0 &&
        pid != 0 && pid < 0x00ffffff)
      out_pids[n++] = (pid_t)pid;
    unsigned long next = 0;
    if (kernel_copyout(kaddr + PROC_OFF_NEXT, &next, sizeof(next)) != 0)
      break;
    if (next == kaddr)
      break;
    kaddr = next;
  }
  return n;
}

/* SceShellUI is the only process with the ReactNative shell modules
 * (proven discriminators).  FALLBACK discovery path only: the sysctl
 * name scan (below) is the primary - this allproc walk with
 * per-process dynlib probes is far more expensive per tick. */
static const char *const kShellUiModules[] = {
    "Sce.Vsh.ShellUI.ReactNativeShellApp.dll.sprx",
    "Sce.Vsh.ShellUI.ReactNativeApps.dll.sprx",
};

static pid_t rc_find_shellui_modules(void) {
  pid_t pids[512];
  size_t n = load_procs(pids, sizeof(pids) / sizeof(pids[0]));

  for (size_t i = 0; i < n; i++) {
    for (size_t m = 0; m < sizeof(kShellUiModules) / sizeof(kShellUiModules[0]);
         m++) {
      uint32_t hk = 0;
      if (kernel_dynlib_handle(pids[i], kShellUiModules[m], &hk) == 0 && hk)
        return pids[i];
    }
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* SceShellUI discovery + restart watch (proven parity: the sysctl      */
/* find_pid scan + the kqueue NOTE_EXEC watcher on SceSysCore.elf).     */

/* One sysctl(KERN_PROC) scan: mib {1,14,8,0} = CTL_KERN / KERN_PROC /
 * KERN_PROC_PROC / all.  Records are variable-length: ki_structsize
 * @+0x00 is the stride, ki_pid @+0x48 (72), thread name @+0x1BF (447)
 * - constants that hold on every supported firmware. */
static int rc_proc_walk(void (*cb)(pid_t, const char *, void *), void *arg) {
  int mib[4] = {1, 14, 8, 0};
  size_t buf_size = 0;
  uint8_t *buf;

  if (sysctl(mib, 4, NULL, &buf_size, NULL, 0) != 0 || buf_size == 0)
    return -1;
  buf = (uint8_t *)malloc(buf_size);
  if (!buf)
    return -1;
  if (sysctl(mib, 4, buf, &buf_size, NULL, 0) != 0) {
    free(buf);
    return -1;
  }
  for (uint8_t *p = buf; p + 4 <= buf + buf_size;) {
    int kisz = *(int *)p;
    const uint8_t *kiname;

    if (kisz < 448 || (size_t)kisz > (size_t)(buf + buf_size - p))
      break; /* corrupt / truncated record: stop, don't loop forever */
    kiname = p + 447;
    if (!memchr(kiname, '\0', (size_t)(buf + buf_size - kiname)))
      break; /* name not NUL-terminated inside the buffer: stop - a
              * bare strcmp here could read past the record (and past
              * the malloc'd buffer on the last record) */
    cb(*(pid_t *)&p[72], (const char *)kiname, arg);
    p += kisz;
  }
  free(buf);
  return 0;
}

struct rc_find_ctx {
  const char *want;
  pid_t mypid;
  pid_t found;
};

static void rc_cb_find(pid_t pid, const char *name, void *arg) {
  struct rc_find_ctx *c = (struct rc_find_ctx *)arg;
  if (pid > 0 && pid != c->mypid && strcmp(name, c->want) == 0)
    c->found = pid;
}

/* sysctl find_pid(): >0 = pid found, 0 = scan ok / process absent,
 * -1 = sysctl failed (caller falls back to the module walk) */
static pid_t rc_find_pid(const char *name) {
  struct rc_find_ctx c = {name, getpid(), 0};

  if (rc_proc_walk(rc_cb_find, &c) != 0)
    return -1;
  return c.found;
}

struct rc_name_ctx {
  pid_t want;
  char *out;
  size_t outsz;
  int hit;
};

static void rc_cb_name(pid_t pid, const char *name, void *arg) {
  struct rc_name_ctx *c = (struct rc_name_ctx *)arg;
  if (pid == c->want) {
    snprintf(c->out, c->outsz, "%s", name);
    c->hit = 1;
  }
}

/* reverse lookup for the kqueue events: name of a specific pid */
static int rc_pid_name(pid_t want, char *out, size_t outsz) {
  struct rc_name_ctx c = {want, out, outsz, 0};

  out[0] = '\0';
  if (rc_proc_walk(rc_cb_name, &c) != 0)
    return -1;
  return c.hit ? 0 : -1;
}

/* primary discovery: one cheap sysctl name scan per
 * tick; the expensive module walk only runs if the sysctl path fails */
static pid_t rc_find_shellui(void) {
  pid_t pid = rc_find_pid("SceShellUI");
  if (pid >= 0)
    return pid;
  return rc_find_shellui_modules();
}

/* restart mechanism: kqueue EVFILT_PROC on SceSysCore.elf with
 * NOTE_FORK|NOTE_EXEC|NOTE_TRACK - every child exec surfaces here, so
 * a fresh SceShellUI (rest mode, crash recovery) is noticed instantly.
 * Instead of a sceKernelGetAppInfo title_id filter the exec'd
 * pid is re-checked by name through the same sysctl scan.  Self-
 * healing: NOTE_EXIT / kevent timeouts re-validate SceSysCore and
 * re-register; a hard kqueue failure just disables the watch (the
 * 250ms tick discovery keeps working on its own). */
static volatile pid_t g_kq_shellui; /* exec event: fresh SceShellUI pid */

/* plog from the kqueue thread: same FILE* as the other threads, so the
 * line is formatted first and emitted under g_kmtx */
static void plog_kq(const char *fmt, ...) {
  char line[768];
  va_list ap;

  va_start(ap, fmt);
  vsnprintf(line, sizeof(line), fmt, ap);
  va_end(ap);
  pthread_mutex_lock(&g_kmtx);
  plog("%s", line);
  pthread_mutex_unlock(&g_kmtx);
}

static void *rc_kq_thread(void *arg) {
  (void)arg;

  plog_kq("KQ: restart watcher started\n");
  for (;;) {
    pid_t syscore = rc_find_pid("SceSysCore.elf");
    time_t last_check = time(NULL);
    int kq;
    struct kevent kev;

    if (syscore <= 0) {
      sleep(1);
      continue;
    }
    kq = kqueue();
    if (kq < 0) {
      plog_kq("KQ: kqueue failed errno=%d - restart watch OFF "
              "(tick discovery keeps working)\n",
              errno);
      return NULL;
    }
    EV_SET(&kev, (uintptr_t)syscore, EVFILT_PROC,
           EV_ADD | EV_ENABLE | EV_CLEAR,
           NOTE_FORK | NOTE_EXEC | NOTE_TRACK | NOTE_EXIT, 0, NULL);
    if (kevent(kq, &kev, 1, NULL, 0, NULL) < 0) {
      plog_kq("KQ: kevent register failed errno=%d - restart watch OFF\n",
              errno);
      close(kq);
      return NULL;
    }
    plog_kq("KQ: watching SceSysCore.elf (pid=%d) for ShellUI execs\n",
            syscore);
    for (;;) {
      struct kevent ev;
      struct timespec ts = {5, 0};
      int nev = kevent(kq, NULL, 0, &ev, 1, &ts);

      if (nev == 0) { /* timeout: re-validate the watched process */
        time_t now = time(NULL);
        if (now - last_check >= 10) {
          last_check = now;
          pid_t sc = rc_find_pid("SceSysCore.elf");
          if (sc != syscore && sc != -1)
            break; /* restarted (new pid) or gone: re-register */
        }
        continue;
      }
      if (nev < 0) {
        plog_kq("KQ: kevent failed errno=%d - re-registering\n", errno);
        break;
      }
      if (ev.fflags & NOTE_EXIT) {
        /* only the WATCHED process's exit tears the registration down;
         * tracked children exit all the time and their NOTE_EXITs
         * arrive on the same kqueue (NOTE_TRACK) */
        if ((pid_t)ev.ident == syscore)
          break;
        continue;
      }
      if (!(ev.fflags & NOTE_EXEC))
        continue;
      {
        pid_t np = (pid_t)ev.ident;
        char name[32];

        if (rc_pid_name(np, name, sizeof(name)) != 0 ||
            strcmp(name, "SceShellUI") != 0)
          continue; /* some other child exec'd (games etc.) */
        /* set the kick under g_kmtx: the poller reads and consumes it
         * under the same lock, so a kick cannot be lost in the window
         * between the poller's read and reset */
        pthread_mutex_lock(&g_kmtx);
        plog("KQ: SceShellUI exec detected (pid=%d) - poller kick\n", np);
        g_kq_shellui = np;
        pthread_mutex_unlock(&g_kmtx);
      }
    }
    close(kq);
    usleep(500 * 1000); /* every break path lands here: a short pause
                         * keeps a persistently failing kevent from
                         * busy-looping the re-register cycle */
  }
}

/* ------------------------------------------------------------------ */
/* vm_map walk (splay tree, FW 11.20 layout)                           */

#define RC_OFF_VMSPACE_ROOT 0x1d0ull /* KERNEL_OFFSET_VMSPACE_P_ROOT */

struct rc_vme {
  uint64_t start;
  uint64_t end;
  uint8_t prot;
};

#define RC_MAX_ENTRIES 24576

/* mirror of SDK kernel_is_heap_addr: rejects NULL/misaligned/non-kernel
 * and - critically - kernel .text/.rodata windows (hi16 0x0000/0xffff) */
static int rc_kptr_ok(uint64_t p) {
  unsigned int hi;

  if (!p || (p & 7))
    return 0;
  if ((p >> 48) != 0xffffull)
    return 0;
  hi = (unsigned int)((p >> 32) & 0xffffull);
  if (hi == 0 || hi == 0xffff)
    return 0;
  return 1;
}

/* collect the readable vm_map entries of pid (in-order tree walk).
 * *reason reports how the walk ended: 0 = clean list end, 1 = cap
 * reached, 2 = bad entry (en<=st or kernel-space start), 3 = non-
 * ascending start (cycle/corrupt chain), 4 = copyout failed, 5 = dead
 * link (failed the kernel-heap heuristic) */
static int rc_vmwalk(pid_t pid, struct rc_vme *out, int max, int *reason,
                     int *seen_out) {
  uint64_t proc, vmspace = 0, root = 0, e, next;
  int n = 0, i, seen = 0;
  uint64_t last = 0;

  if (reason)
    *reason = 0;
  if (seen_out)
    *seen_out = 0;
  if (!(proc = (uint64_t)kernel_get_proc(pid)))
    return -1;
  if (kernel_copyout(proc + KERNEL_OFFSET_PROC_P_VMSPACE, &vmspace,
                     sizeof(vmspace)))
    return -1;
  if (!rc_kptr_ok(vmspace))
    return -2;
  if (kernel_copyout(vmspace + RC_OFF_VMSPACE_ROOT, &root, sizeof(root)))
    return -1;
  if (!rc_kptr_ok(root))
    return -3;

  /* leftmost entry = tree minimum */
  e = root;
  for (i = 0; i < 4096; i++) {
    if (!rc_kptr_ok(e))
      return -4;
    if (kernel_copyout(e + 0x10, &next, sizeof(next)))
      return -1;
    if (!next)
      break;
    e = next;
  }

  /* in-order successor chain (+0x08), same iteration the SDK uses */
  for (i = 0; i < 65536; i++) {
    uint64_t st = 0, en = 0;
    uint8_t pr = 0;

    if (!rc_kptr_ok(e)) {
      if (reason)
        *reason = 5;
      break;
    }
    if (kernel_copyout(e + 0x20, &st, sizeof(st)) ||
        kernel_copyout(e + 0x28, &en, sizeof(en)) ||
        kernel_copyout(e + 0x64, &pr, sizeof(pr)))
      return -1;
    seen++;
    if (en <= st || st >= 0xffff800000000000ull) {
      if (reason)
        *reason = 2;
      break;
    }
    if (last && st < last) {
      if (reason)
        *reason = 3; /* cycle or corrupt chain */
      break;
    }
    last = st;
    if ((pr & 0x01) && n < max) {
      out[n].start = st;
      out[n].end = en;
      out[n].prot = pr;
      n++;
    } else if (n >= max && reason) {
      *reason = 1;
    }
    if (kernel_copyout(e + 0x08, &next, sizeof(next)))
      return -1;
    if (!next) {
      if (reason)
        *reason = 0;
      break;
    }
    e = next;
  }
  if (seen_out)
    *seen_out = seen;
  return n;
}

/* ------------------------------------------------------------------ */
/* signature scan + call-site substitution                             */

enum pass_result {
  PASS_NONE = 0,    /* sig not found in this pass                */
  PASS_PATCHED,     /* found unpatched copy, patches written     */
  PASS_ALREADY,     /* only already-patched copies were found    */
  PASS_ERROR        /* vmwalk / ctx failure                      */
};

/* Apply all sites to one known NPXS40003 HBC copy.
 * Returns how many sites were newly patched; *already / *bad receive
 * the counts of already-patched and unrecognizable sites.  A site is
 * recognized when its signature matches around a 2-byte operand that
 * is either the original value (patch it) or already the site's
 * replacement (skip). */
static uint64_t g_last_anomaly_base; /* per-copy log throttle */

static int rc_apply_sites(pid_t pid, uint64_t hbc_base, uint64_t region_end,
                          int *already, int *bad) {
  int patched = 0;

  *already = 0;
  *bad = 0;
  for (size_t i = 0; i < RC_SITE_N; i++) {
    const struct rc_site *st = &RC_SITES[i];
    uint64_t va = hbc_base + st->sig_hbc_off;
    uint8_t win[RC_SIG_MAX], chk[2];

    if (st->sig_len > sizeof(win) || va + st->sig_len > region_end ||
        proc_read_dmap(pid, va, win, st->sig_len) != 0) {
      (*bad)++;
      if (hbc_base != g_last_anomaly_base) {
        g_last_anomaly_base = hbc_base;
        plog("PATCH: %s unreadable @0x%012llx\n", st->name,
             (unsigned long long)va);
      }
      continue;
    }
    if (memcmp(win, st->sig, st->op_off) != 0 ||
        memcmp(win + st->op_off + 2, st->sig + st->op_off + 2,
               st->sig_len - st->op_off - 2) != 0 ||
        (memcmp(win + st->op_off, st->sig + st->op_off, 2) != 0 &&
         memcmp(win + st->op_off, st->new2, 2) != 0)) {
      (*bad)++;
      if (hbc_base != g_last_anomaly_base) {
        g_last_anomaly_base = hbc_base;
        plog("PATCH: %s signature mismatch @0x%012llx - different bundle?\n",
             st->name, (unsigned long long)va);
      }
      continue;
    }
    if (memcmp(win + st->op_off, st->new2, 2) == 0) {
      (*already)++;
      continue; /* already-patched site */
    }
    if (proc_write_dmap(pid, va + st->op_off, st->new2, 2) != 0 ||
        proc_read_dmap(pid, va + st->op_off, chk, 2) != 0 ||
        memcmp(chk, st->new2, 2) != 0) {
      (*bad)++;
      if (hbc_base != g_last_anomaly_base) {
        g_last_anomaly_base = hbc_base;
        plog("PATCH: %s write/verify FAILED @0x%012llx\n", st->name,
             (unsigned long long)(va + st->op_off));
      }
      continue;
    }
    patched++;
    plog("PATCH: %s @0x%012llx id16 ->%02X%02X (hbc_base=0x%012llx)\n",
         st->name, (unsigned long long)(va + st->op_off), st->new2[0],
         st->new2[1], (unsigned long long)hbc_base);
  }
  return patched;
}

/* sanity-check that va really hosts an NPXS40003 Hermes copy: triple
 * identification - magic8 + bytecode version @0x08 + fileLength
 * @0x20, all from ONE 0x24-byte read (proc_read_dmap is chunked per
 * page, so a page-boundary crossing inside the header is safe) */
static int rc_hbc_sane(pid_t pid, uint64_t va) {
  uint8_t hdr[0x24];
  uint32_t ver, flen;

  if (proc_read_dmap(pid, va, hdr, sizeof(hdr)) != 0 ||
      memcmp(hdr, RC_HBC_MAGIC8, sizeof(RC_HBC_MAGIC8)) != 0)
    return 0;
  memcpy(&ver, hdr + 0x08, sizeof(ver));
  memcpy(&flen, hdr + 0x20, sizeof(flen));
  return ver == RC_HBC_VERSION && flen == RC_HBC_FILELEN;
}

/* known-copy table helper (defined below; g_kmtx held at every call) */
static void rc_base_add(uint64_t base);

/* scan readable regions of pid for any site signature; on the first
 * recognized copy apply ALL sites at their fixed HBC offsets.  Keeps
 * scanning past already-patched copies (several container generations
 * can be resident at once); returns the pass result. */
static enum pass_result patch_pass(pid_t pid) {
  static struct rc_vme *ents;
  static uint8_t buf[RC_SIG_MAX - 1 + 0x1000];
  int n, reason = 0, seen = 0, skipro = 0, skipn = 0, skiphi = 0, regs = 0;
  uint64_t scanned = 0;
  enum pass_result res = PASS_NONE;
  bool saw_copy = false;

  if (!ents) {
    ents = (struct rc_vme *)malloc(sizeof(struct rc_vme) * RC_MAX_ENTRIES);
    if (!ents) {
      plog("PASS: entry table malloc failed\n");
      return PASS_ERROR;
    }
  }

  n = rc_vmwalk(pid, ents, RC_MAX_ENTRIES, &reason, &seen);
  if (n < 0) {
    plog("PASS: vmwalk failed rc=%d reason=%d seen=%d\n", n, reason, seen);
    return PASS_ERROR;
  }

  time_t t0 = time(NULL);
  for (int i = 0; i < n && res != PASS_PATCHED; i++) {
    uint64_t a, end = ents[i].end, rsz = end - ents[i].start;

    if (end <= ents[i].start || !(ents[i].prot & 0x01)) {
      skipro++;
      continue;
    }
    if (rsz < RC_HBC_FILELEN) {
      skipn++;
      continue;
    }
    /* RN heap sits around 0x8_1c0000000 (~522GB) - the old 64GB cap
     * skipped exactly the region we need */
    if (ents[i].start >= 0x10000000000ull) { /* 1TB */
      skiphi++;
      continue;
    }
    regs++;
    memset(buf, 0, RC_SIG_MAX - 1); /* no sig carry across regions */
    for (a = ents[i].start & ~0xfffull;
         a + 0x1000 <= end && res != PASS_PATCHED; a += 0x1000) {
      if (proc_read_dmap(pid, a, buf + RC_SIG_MAX - 1, 0x1000) != 0) {
        memset(buf, 0, RC_SIG_MAX - 1); /* hole: don't join sig */
        continue;
      }
      scanned += 0x1000;
      /* buf[k] maps to VA a - (RC_SIG_MAX - 1) + k (carry prefix);
       * the loop bound keeps every site window inside read data */
      for (size_t k = 0; k + RC_SIG_MAX <= sizeof(buf); k++) {
        uint64_t hit, hbc_base;
        int already = 0, bad = 0, patched;
        const uint8_t b0 = buf[k];

        if (b0 != 0x2E && b0 != 0x94 && b0 != 0x51) /* first byte of 7
                                                     * of the 8 sigs; S8
                                                     * starts with 0x03
                                                     * (NewObject - far too
                                                     * common to filter on)
                                                     * and is reached by
                                                     * rc_apply_sites once
                                                     * any other sig of the
                                                     * same copy matched */
          continue;
        bool matched = false;
        for (size_t s = 0; s < RC_SITE_N && !matched; s++) {
          const struct rc_site *st = &RC_SITES[s];
          if (buf[k] != st->sig[0] ||
              memcmp(buf + k, st->sig, st->op_off) != 0 ||
              memcmp(buf + k + st->op_off + 2, st->sig + st->op_off + 2,
                     st->sig_len - st->op_off - 2) != 0)
            continue;
          /* op bytes: original value or already-substituted - both
           * identify the copy; anything else is not our bundle */
          if (memcmp(buf + k + st->op_off, st->sig + st->op_off, 2) != 0 &&
              memcmp(buf + k + st->op_off, st->new2, 2) != 0)
            continue;
          hit = a - (RC_SIG_MAX - 1) + k;
          hbc_base = hit - st->sig_hbc_off;
          matched = true;

          if (!rc_hbc_sane(pid, hbc_base)) {
            plog("PASS: sig @0x%012" PRIx64 " but Hermes triple-ID "
                 "missing - skip\n",
                 hit);
            continue; /* try the remaining sigs at this k */
          }
          saw_copy = true;
          rc_base_add(hbc_base); /* seed rotation + steady revision */
          rc_repair_legacy(pid, hbc_base, end);
          patched = rc_apply_sites(pid, hbc_base, end, &already, &bad);
          if (patched > 0)
            res = PASS_PATCHED;
          else if (bad == 0 && already == (int)RC_SITE_N &&
                   res == PASS_NONE)
            res = PASS_ALREADY;
          k += RC_SIG_MAX - 1; /* skip past this window */
          break;
        }
        if (matched)
          break; /* resume at the next page (carry keeps context) */
      }
      memcpy(buf, buf + 0x1000, RC_SIG_MAX - 1); /* tail for next page */
    }
  }

  plog("PASS: pid=%d entries=%d walked=%d stop=%d regs=%d "
       "skip(ro/small/high)=%d/%d/%d scanned=%lluMB took=%ds -> %s\n",
       pid, n, seen, reason, regs, skipro, skipn, skiphi,
       (unsigned long long)(scanned >> 20), (int)(time(NULL) - t0),
       res == PASS_PATCHED  ? "PATCHED"
       : res == PASS_ALREADY ? "ALREADY"
       : res == PASS_ERROR   ? "ERROR"
       : saw_copy            ? "PARTIAL"
                             : "NONE");

  return res;
}

/* known-copy table helpers (g_kmtx held: poller and main loop are the
 * only users) */
static void rc_base_add(uint64_t base) {
  for (int i = 0; i < g_poll_nbases; i++)
    if (g_poll_bases[i] == base)
      return; /* already tracked */
  if (g_poll_nbases == RC_MAX_BASES) {
    /* table full: drop the oldest entry (shift left) */
    for (int i = 1; i < RC_MAX_BASES; i++)
      g_poll_bases[i - 1] = g_poll_bases[i];
    g_poll_nbases--;
  }
  g_poll_bases[g_poll_nbases++] = base;
  plog("JWFAST: tracking copy #%d hbc_base=0x%012llx\n", g_poll_nbases,
       (unsigned long long)base);
  /* an open seed window must cover copies discovered mid-window
   * (the persist-seed window); both callers hold g_kmtx */
  if (g_seed_deadline && g_shellui_pid) {
    int r = rc_seed_write(g_shellui_pid, base, true);
    if (r == 2)
      plog("SEED: fresh copy seeded @0x%012llx\n",
           (unsigned long long)(base + RC_SEED_HBC_OFF));
  }
}

static void rc_base_drop(int idx) {
  if (idx < 0 || idx >= g_poll_nbases)
    return;
  for (int i = idx + 1; i < g_poll_nbases; i++)
    g_poll_bases[i - 1] = g_poll_bases[i];
  g_poll_nbases--;
}

/* Seed-window lifecycle.  Runs every poller tick with g_kmtx
 * held; IO happens only on the open/close transitions.  A window is
 * armed on EVERY known copy: during the window any object-param
 * removeActionCard of an EXISTING card takes the HARD+persist path
 * (the S7-forced funnel cycle on the next context change provides the
 * removal as soon as the card is present), so one window after a
 * generation start is usually enough to latch the persist entry -
 * after that F#2957 throws on every re-add attempt and the card stays
 * dead across restarts (the KV entry survives ShellUI restarts and is
 * re-loaded by the UNTOUCHED loadPersistedRemovedCards). */
static void rc_seed_tick(pid_t pid, time_t now) {
  if (g_seed_deadline) {
    if (now < g_seed_deadline)
      return; /* window still open */
    /* close: restore the original GetByIds on every known copy */
    int ok = 0, skip = 0, fail = 0;
    for (int i = 0; i < g_poll_nbases; i++) {
      int r = rc_seed_write(pid, g_poll_bases[i], false);
      if (r > 0)
        ok++;
      else if (r < 0)
        fail++;
      else
        skip++;
    }
    plog("SEED: window closed after %ds - reverted ok=%d skip=%d fail=%d\n",
         RC_SEED_WINDOW_SEC, ok, skip, fail);
    g_seed_deadline = 0;
    /* a close that reverted NOTHING (copies unreadable / foreign bytes)
     * leaves the seed bytes live in memory - re-open soon instead of
     * idling out the full 30 min with the window bytes stuck applied */
    g_seed_next = now + ((ok > 0 && fail == 0) ? RC_SEED_RETRY_SEC : 60);
    return;
  }
  if (!pid || now < g_seed_next)
    return;
  if (g_poll_nbases == 0) {
    g_seed_next = now + RC_SEED_NOTYET_SEC; /* no copy yet */
    return;
  }
  int armed = 0, already = 0, fail = 0, skip = 0;
  for (int i = 0; i < g_poll_nbases; i++) {
    int r = rc_seed_write(pid, g_poll_bases[i], true);
    if (r == 2)
      armed++;
    else if (r == 1)
      already++;
    else if (r < 0)
      fail++;
    else
      skip++; /* copy unreadable: not a write failure */
  }
  if (armed + already > 0) {
    g_seed_deadline = now + RC_SEED_WINDOW_SEC;
    plog("SEED: window OPEN for %ds on %d copy(ies) (written=%d already=%d "
         "fail=%d) - obj-param removeActionCard now persists\n",
         RC_SEED_WINDOW_SEC, g_poll_nbases, armed, already, fail);
  } else {
    plog("SEED: arm skipped (fail=%d skip=%d) - retry in 60s\n", fail, skip);
    g_seed_next = now + 60;
  }
}

/* ------------------------------------------------------------------ */
/* JWFAST poller thread: owns ShellUI discovery (sysctl name scan),    */
/* slab probing, legacy repair and the call-site substitutions.         */
/* SCAN state: catches a fresh HBC copy within ~300ms of its decrypt    */
/* (well before the service's first update cycle).  STEADY state: a     */
/* cheap revision of the cached copy every 2s (the HBC header + the
 * sites at the cached base, ~8 dmap reads instead of the vmwalk +
 * probe ~13K) once every found copy is patched (the per-generation
 * model).  A sanity FAIL on a magic hit is a foreign Hermes bundle
 * (NPXS40025/40002/... share the magic) - an expected probe outcome,
 * NOT a retry cause: it neither sets any_bad nor blocks STEADY.  The
 * persist-seed window lifecycle runs alongside in the same
 * loop. */

enum rc_poll_state { RC_ST_SCAN = 0, RC_ST_STEADY };

static void *rc_fast_thread(void *arg) {
  (void)arg;
  pid_t last_pid = 0;
  uint64_t patched = 0;
  int state = RC_ST_SCAN;
  time_t last_scan = 0; /* when the last probe scan actually ran      */
  time_t last_deep = 0; /* when the last full content rescan ran       */

  plog("JWFAST: patch-on-decrypt prober started (250ms, sysctl-scan "
       "discovery)\n");
  while (g_run) {
    usleep(POLL_TICK_US);
    pthread_mutex_lock(&g_kmtx);

    /* cheap discovery: one sysctl name scan per tick */
    pid_t pid = rc_find_shellui();
    if (pid != last_pid) {
      plog("JWFAST: SceShellUI %s (pid=%d)\n",
           pid ? (last_pid ? "restarted" : "found") : "gone", pid);
      last_pid = pid;
      g_shellui_pid = pid;
      g_poll_epoch_magic = 0;
      g_poll_nbases = 0; /* fresh generation: no known copies */
      /* fresh generation: any seed window is void (its copies are
       * gone); schedule the first one right after discovery - the CC
       * init push (the resurrection moment) lands seconds later */
      g_seed_deadline = 0;
      g_seed_next = time(NULL) + RC_SEED_START_DELAY_SEC;
      /* first deep rescan 25 s after discovery: keeps the boot-critical
       * window free of the ~2 s full content pass */
      last_deep = time(NULL) - (RC_DEEP_SCAN_SEC - 25);
      if (!pid)
        g_notified = false;
      state = RC_ST_SCAN; /* fresh generation: aggressive mode */
      last_scan = 0;
    }
    g_poll_ticks++;

    /* kqueue restart watch: a fresh SceShellUI exec'd - scan right now
     * instead of waiting for the next discovery tick */
    bool kick = g_kq_shellui != 0;
    g_kq_shellui = 0;
    if (kick) {
      state = RC_ST_SCAN;
      g_poll_nbases = 0; /* kicked by a fresh exec: rediscover */
      /* fresh exec = fresh generation: re-arm the seed window */
      g_seed_deadline = 0;
      g_seed_next = time(NULL) + RC_SEED_START_DELAY_SEC;
      plog("JWFAST: kqueue kick -> aggressive scan\n");
    }

    time_t now = time(NULL);
    bool due = pid && (kick || state == RC_ST_SCAN ||
                       now - last_scan >= RC_REVERIFY_SEC);

    if (pid && due) {
      if (state == RC_ST_STEADY && g_poll_nbases > 0) {
        /* cheap STEADY revision: every known copy of this generation
         * (header + the sites each, ~8 dmap reads per copy
         * instead of the vmwalk + probe ~13K).  A bad site means the
         * copy was unmapped / replaced (or a foreign bundle sat
         * there): drop it; an empty table falls back to the
         * aggressive probe scan. */
        int total_np = 0, dropped = 0;
        for (int bi = g_poll_nbases - 1; bi >= 0; bi--) {
          uint64_t base = g_poll_bases[bi];
          int already = 0, bad = 0;
          int np = rc_apply_sites(pid, base, base + RC_HBC_FILELEN,
                                  &already, &bad);
          if (bad > 0) {
            plog("JWFAST: steady revision FAILED (hbc_base=0x%012llx) "
                 "- dropped\n",
                 (unsigned long long)base);
            rc_base_drop(bi);
            dropped++;
          } else if (np > 0) {
            total_np += np;
            plog("JWFAST: steady revision patched %d site(s) "
                 "(hbc_base=0x%012llx) tick=%llu\n",
                 np, (unsigned long long)base,
                 (unsigned long long)g_poll_ticks);
          }
        }
        if (g_poll_nbases == 0) {
          state = RC_ST_SCAN; /* nothing left to revise: rediscover */
        } else {
          if (dropped == 0)
            g_poll_epoch_magic++; /* poller-liveness signal */
          if (total_np > 0) {
            patched++;
            state = RC_ST_SCAN; /* a live site was unpatched: re-probe */
          }
        }
      } else {
        /* full probe scan (SCAN state, or the cached copy is gone) */
        static struct rc_vme *ents; /* g_kmtx held: single user */
        int n = 0, sane = 0;
        bool any_patched = false, any_bad = false;
        if (!ents) {
          ents = (struct rc_vme *)malloc(sizeof(struct rc_vme) *
                                         RC_MAX_ENTRIES);
          if (!ents)
            plog("JWFAST: entry table malloc failed\n");
        }
        if (ents)
          n = rc_vmwalk(pid, ents, RC_MAX_ENTRIES, NULL, NULL);
        for (int i = 0; n > 0 && i < n; i++) {
          uint64_t end = ents[i].end, rsz = end - ents[i].start;
          if (end <= ents[i].start || !(ents[i].prot & 0x01) ||
              rsz < 0x100000ull || ents[i].start >= 0x10000000000ull)
            continue;
          /* one 8-byte magic window per 1MB slab, both probe
           * families */
          for (uint64_t a = (ents[i].start + 0xfffff) & ~0xfffffull;
               a + 0x5000 <= end; a += 0x100000) {
            for (int fam = 0; fam < RC_SLAB_N; fam++) {
              uint64_t va = a + rc_slab_off[fam];
              uint64_t m;
              if (va + 8 > end)
                continue;
              g_poll_probes++;
              if (proc_read_dmap(pid, va, &m, sizeof(m)) != 0 ||
                  m != RC_MAGIC8)
                continue;
              g_poll_magic++;
              /* an HBC copy lives here: triple-check, repair any
               * retired-patch leftovers, then substitute.  A sanity FAIL
               * is a foreign Hermes bundle (NPXS40025/40002/...
               * share the magic) - an expected probe outcome, NOT
               * a retry cause. */
              int already = 0, bad = 0, np;
              if (!rc_hbc_sane(pid, va))
                continue;
              sane++;
              rc_base_add(va); /* track for the STEADY revision */
              rc_repair_legacy(pid, va, end);
#if RSH_TYPE_STRING_PATCH
              rc_kill_type_string(pid, va); /* retired site (optional) */
#endif
              np = rc_apply_sites(pid, va, end, &already, &bad);
              if (bad > 0)
                any_bad = true;
              if (np > 0) {
                any_patched = true;
                patched++;
                plog("JWFAST: %d/%d site(s) patched (hbc_base=0x%012llx) "
                     "tick=%llu\n",
                     np, (int)RC_SITE_N, (unsigned long long)va,
                     (unsigned long long)g_poll_ticks);
                if (!g_notified) {
                  notify("RecentScreenshotsHider: recent screenshots hidden");
                  g_notified = true;
                }
              }
            }
          }
        }
        /* cadence: aggressive until everything found is
         * patched; STEADY only once a confirmed copy exists (the
         * cheap revision needs a cached base) */
        if (sane > 0) {
          if (any_patched || any_bad) {
            state = RC_ST_SCAN; /* fresh copy patched / retry needed */
          } else if (state == RC_ST_SCAN) {
            state = RC_ST_STEADY;
            plog("JWFAST: %d copy(ies) already patched - steady mode "
                 "(cheap revision every %ds)\n",
                 sane, RC_REVERIFY_SEC);
          }
        }
      }
    }
    /* periodic deep rescan: the 1MB-family probe and the
     * known-copy revision miss (a) fresh copies mapped into the same
     * process by an RNPS reload / bundle re-decrypt and (b) copies at
     * offsets outside the probe families.  patch_pass content-scans
     * every readable region and patches the first unpatched copy it
     * meets (~2 s under the mutex). */
    if (pid && now - last_deep >= RC_DEEP_SCAN_SEC) {
      last_deep = now;
      enum pass_result deep = patch_pass(pid);
      if (deep == PASS_PATCHED) {
        patched++;
        state = RC_ST_SCAN; /* re-discover / re-cache every copy */
        plog("JWFAST: deep rescan patched a fresh copy -> rediscover\n");
      }
    }
    /* persist-seed window lifecycle (IO only on transitions) */
    rc_seed_tick(pid, now);
    if (due)
      last_scan = now; /* stamp only real scans: stamping every tick
                        * (per state) would starve the STEADY re-verify
                        * forever and leave fresh copies unpatched */

    /* stats line inside the lock: plog from two threads must not
     * interleave in the same FILE* (main loop logs FALLBACK under it) */
    if ((g_poll_ticks % 40) == 0)
      plog("JWFAST: ticks=%llu probes=%llu magic=%llu patched=%llu "
           "epoch=%llu pid=%d state=%s\n",
           (unsigned long long)g_poll_ticks,
           (unsigned long long)g_poll_probes,
           (unsigned long long)g_poll_magic,
           (unsigned long long)patched,
           (unsigned long long)g_poll_epoch_magic, g_shellui_pid,
           state == RC_ST_STEADY ? "STEADY" : "SCAN");

    pthread_mutex_unlock(&g_kmtx);
  }
  plog("JWFAST: stopped\n");
  return NULL;
}

/* ------------------------------------------------------------------ */
/* main                                                                */

int main(void) {
  uint64_t saved_authid = 0;

  syscall(SYS_thr_set_name, -1, PAYLOAD_NAME);

  if (mkdir("/data/homebrew", 0777) != 0 && errno != EEXIST)
    printf("mkdir /data/homebrew FAILED errno=%d\n", errno);
  clock_gettime(CLOCK_MONOTONIC, &g_log_t0); /* [+ss.sss] stamp origin */
  g_log = fopen(LOG_PATH, "a");
  if (!g_log) {
    printf("cannot open %s, logging to stdout only\n", LOG_PATH);
  } else {
    setvbuf(g_log, NULL, _IONBF, 0);
    /* PLK does not show stdout: tee to the same file */
    if (!freopen(LOG_PATH, "a", stdout)) {
      /* keep g_log as the only sink */
    }
    setvbuf(stdout, NULL, _IONBF, 0);
  }

  plog("recent-screenshots-hider %s starting (pid=%ld fw=0x%x)\n",
       RSH_VERSION,
       (long)getpid(), (unsigned)kernel_get_fw_version());

  if (!elevate(&saved_authid)) {
    plog("ABORT: no elevation\n");
    notify("RecentScreenshotsHider: elevation FAILED");
    return 1;
  }
  if (self_test() != 0) {
    plog("ABORT: self-test failed\n");
    notify("RecentScreenshotsHider: self-test FAILED");
    kernel_set_ucred_authid(getpid(), saved_authid);
    return 1;
  }

  /* JWFAST poller: owns ShellUI discovery (sysctl name scan), slab
   * probing and the call-site substitutions.  The main loop only
   * monitors and runs the full scan as a fallback when the poller has
   * been blind for the current pid (unexpected heap geometry, or the
   * poller thread failed to spawn). */
  pthread_t poller;
  bool have_poller = (pthread_create(&poller, NULL, rc_fast_thread, NULL) == 0);
  if (!have_poller)
    plog("JWFAST: thread spawn FAILED (errno=%d) - full-scan fallback only\n",
         errno);

  /* restart watch: kqueue NOTE_EXEC on SceSysCore.elf kicks the
   * poller the moment a fresh SceShellUI instance execs.  The thread
   * is auxiliary - if it cannot start, the per-tick discovery still
   * catches restarts within 250ms. */
  pthread_t kqt;
  if (pthread_create(&kqt, NULL, rc_kq_thread, NULL) == 0)
    pthread_detach(kqt);
  else
    plog("KQ: thread spawn FAILED (errno=%d) - tick discovery only\n", errno);

  pid_t fb_pid = 0;    /* pid the fallback is tracking   */
  time_t fb_since = 0; /* when that pid first appeared   */
  time_t fb_last = 0;  /* last fallback pass             */

  while (true) {
    sleep(POLL_PROBE_SEC);
    pthread_mutex_lock(&g_kmtx);
    pid_t pid = g_shellui_pid;
    time_t now = time(NULL);

    if (!have_poller) {
      /* the poller owns discovery; without it g_shellui_pid would stay
       * 0 forever and neither the fallback scan nor the seed lifecycle
       * would ever run - discover on every monitor tick instead */
      pid = rc_find_shellui();
      if (pid != g_shellui_pid) {
        if (pid)
          plog("FALLBACK: SceShellUI discovered (pid=%d)\n", pid);
        g_shellui_pid = pid;
        g_poll_epoch_magic = 0;
        g_poll_nbases = 0; /* fresh generation: no known copies */
        g_seed_deadline = 0;
        g_seed_next = now + RC_SEED_START_DELAY_SEC;
      }
    }

    if (pid != fb_pid) {
      fb_pid = pid;
      fb_since = pid ? now : 0;
    }

    time_t grace = have_poller ? FALLBACK_GRACE_SEC : 0;
    if (pid && g_poll_epoch_magic == 0 && now - fb_since >= grace &&
        now - fb_last >= POLL_RECHECK_SEC) {
      fb_last = now;
      plog("FALLBACK: poller blind for %ds (pid=%d) - full scan\n",
           (int)(now - fb_since), pid);
      enum pass_result st = patch_pass(pid);
      if (st == PASS_PATCHED && !g_notified) {
        notify("RecentScreenshotsHider: recent screenshots hidden");
        g_notified = true;
      }
    }

    if (!have_poller)
      rc_seed_tick(pid, now); /* drive the seed lifecycle too (g_kmtx
                               * held; arm/close are idempotent) */
    pthread_mutex_unlock(&g_kmtx);
  }
  return 0;
}
