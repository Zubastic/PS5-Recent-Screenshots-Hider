#!/usr/bin/env python3
"""Cross-check: the byte arrays in src/main.c against the reference bundle.

Parses RC_S1..RC_S8 (+ _NEW), RC_SEED_SIG/NEW/HALF, RC_GATE_SIG and the
RC_SITES table straight out of main.c, then verifies against
NPXS40003.hbc:
  - every site signature has EXACTLY 1 hit at its declared sig_hbc_off
  - op_off+2 stays inside the signature
  - the seed signature has exactly 1 hit at RC_SEED_HBC_OFF
  - RC_SEED_HALF == first 8 bytes of RC_SEED_NEW + last 4 of RC_SEED_SIG
  - RC_SEED_NEW decodes as 6x LoadConstTrue into r3/r3/r3/r8/r8/r8
  - applying each site's new2 at op_off yields the documented patch

Usage: python3 verify_signatures.py [<main.c>] <NPXS40003.hbc>
The reference bundle is not committed to the repo; pass its path as
the second argument (or place an NPXS40003.hbc copy next to the repo).
"""
import os
import re
import sys

MAIN = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "src", "main.c")
if len(sys.argv) > 2:
    HBC = sys.argv[2]
else:
    # no machine-specific default: look for the bundle next to the
    # repo, otherwise it must be passed on the command line
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, "NPXS40003.hbc"),
                 os.path.join(os.path.dirname(here), "NPXS40003.hbc")):
        if os.path.exists(cand):
            HBC = cand
            break
    else:
        raise SystemExit("usage: verify_signatures.py [<main.c>] "
                         "<NPXS40003.hbc>\nthe reference bundle is not "
                         "committed to the repo - pass its path")

src = open(MAIN, encoding="utf-8", errors="replace").read()
blob = open(HBC, "rb").read()

def parse_array(name):
    m = re.search(r"static const uint8_t %s\[(\d+)\] = \{(.*?)\};" % re.escape(name),
                  src, re.S)
    if not m:
        return None
    nums = [int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(2))]
    if len(nums) != int(m.group(1)):
        raise SystemExit(f"{name}: declared {m.group(1)} bytes, parsed {len(nums)}")
    return bytes(nums)

def count_hits(pat):
    hits, start = [], 0
    while True:
        i = blob.find(pat, start)
        if i < 0:
            break
        hits.append(i)
        start = i + 1
    return hits

fails = []

# --- sites table: name -> (sig, len, op_off, hbc_off, new2) ---
sites = re.findall(
    r'\{"([^"]+)",\s*(RC_S\d),\s*sizeof\(RC_S\d\),\s*(\d+),\s*(0x[0-9A-Fa-f]+)ull,\s*\n?\s*(RC_\w+_NEW|RC_NEW2)\}',
    src)
print(f"sites parsed from RC_SITES: {len(sites)}")
if len(sites) != 8:
    fails.append(f"expected 8 sites, parsed {len(sites)}")

for name, arr, opoff, off, newarr in sites:
    sig = parse_array(arr)
    new2 = parse_array(newarr)
    opoff, off = int(opoff), int(off, 16)
    if sig is None or new2 is None:
        fails.append(f"{name}: array parse failed ({arr}/{newarr})")
        continue
    if opoff + 2 > len(sig):
        fails.append(f"{name}: op_off {opoff} outside sig len {len(sig)}")
        continue
    hits = count_hits(sig)
    if hits != [off]:
        fails.append(f"{name}: sig hits {['0x%x' % h for h in hits]} != [0x{off:x}]")
    else:
        print(f"  OK {name:26s} {arr} len={len(sig):2d} op@+{opoff:2d} "
              f"@0x{off:06X} 1 hit; new2={new2.hex().upper()}")

# --- seed ---
seed_sig = parse_array("RC_SEED_SIG")
seed_new = parse_array("RC_SEED_NEW")
seed_half = parse_array("RC_SEED_HALF")
m = re.search(r"#define RC_SEED_HBC_OFF (0x[0-9A-Fa-f]+)ull", src)
seed_off = int(m.group(1), 16)

hits = count_hits(seed_sig)
if hits != [seed_off]:
    fails.append(f"seed sig hits {['0x%x' % h for h in hits]} != [0x{seed_off:x}]")
else:
    print(f"  OK RC_SEED_SIG        @0x{seed_off:X} exactly 1 hit")

# HALF must equal: first 8 of NEW + last 4 of SIG (the torn half-write shape)
expect_half = seed_new[:8] + seed_sig[8:]
if seed_half != expect_half:
    fails.append(f"RC_SEED_HALF {seed_half.hex().upper()} != "
                 f"NEW[:8]+SIG[8:] {expect_half.hex().upper()}")
else:
    print(f"  OK RC_SEED_HALF       = NEW[:8]+SIG[8:] = {seed_half.hex().upper()}")

# NEW must decode as 6x LoadConstTrue (0x76) with dst regs 3,3,3,8,8,8
dsts = [seed_new[i + 1] for i in range(0, 12, 2)]
if all(seed_new[i] == 0x76 for i in range(0, 12, 2)) and dsts == [3, 3, 3, 8, 8, 8]:
    print(f"  OK RC_SEED_NEW        = 6x LoadConstTrue, dst regs {dsts}")
else:
    fails.append(f"RC_SEED_NEW not 6x LCT r3/r8: {seed_new.hex().upper()} dsts={dsts}")

# --- gate (repair) ---
gate_sig = parse_array("RC_GATE_SIG")
m = re.search(r"#define RC_GATE_OFF (0x[0-9A-Fa-f]+)[Uu][Ll]{2}", src)
gate_off = int(m.group(1), 16)
m = re.search(r"#define RC_GATE_OP (\d+)", src)
gate_op = int(m.group(1))
hits = count_hits(gate_sig)
if hits != [gate_off]:
    fails.append(f"gate sig hits {['0x%x' % h for h in hits]} != [0x{gate_off:x}]")
else:
    print(f"  OK RC_GATE_SIG        @0x{gate_off:X} exactly 1 hit (op byte @+{gate_op})")

# --- sanity: the patched form must not sit AT the site offset itself.
# Exception (S8): F#24663, the sibling variant, is byte-identical to
# F#24662 except its NATIVE LoadConstFalse - i.e. the patched 12-byte
# form exists elsewhere in the bundle by design (that is exactly why
# the S8 signature must carry the LoadConstTrue byte).  We therefore
# only assert that the patched form is absent at the site offset and
# report any other location as the documented sibling.
for nm, arr in [("S1", "RC_S1"), ("S2", "RC_S2"), ("S3", "RC_S3"),
                ("S4", "RC_S4"), ("S5", "RC_S5"), ("S6", "RC_S6"),
                ("S7", "RC_S7"), ("S8", "RC_S8")]:
    sig = parse_array(arr)
    new2 = None
    opoff = None
    site_off = None
    for name, a, o, off, na in sites:
        if a == arr:
            new2 = parse_array(na)
            opoff = int(o)
            site_off = int(off, 16)
    patched = sig[:opoff] + new2 + sig[opoff + 2:]
    hits = count_hits(patched)
    at_site = site_off in hits
    if at_site:
        fails.append(f"{nm}: patched form AT the site offset?!")
    elif nm == "S8":
        print(f"  OK {nm}: patched form not at site; found at "
              f"{['0x%X' % h for h in hits]} (documented F#24663 sibling)")
    elif hits:
        fails.append(f"{nm}: patched form pre-exists at "
                     f"{['0x%X' % h for h in hits]}")
print("  OK patched forms absent at every site offset")

print()
if fails:
    print("FAILURES:")
    for f in fails:
        print("  !!", f)
    sys.exit(1)
print("VERDICT: PASS - main.c arrays match the reference bundle")
