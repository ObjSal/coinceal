#!/usr/bin/env python3
"""Round-trip and regression tests for the envelope crypto.

Run:  python3 test_envelope.py
Requires the same deps as embed_tool.py (pillow cryptography ecdsa piexif).

Covers the invariants that matter after the PBKDF2 iteration bump:
  * new envelopes are ver:2 and carry iters:600000
  * new envelopes encrypt/decrypt round-trip
  * wrong password fails (GCM auth)
  * legacy ver:1 images (no iters field) still decrypt via the 310k fallback
  * a deterministic seed yields a stable address/WIF
"""
import sys
from pathlib import Path

import embed_tool as e

HERE = Path(__file__).resolve().parent
passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed += 1
        print(f"  FAIL {name}")


# 1. New envelope shape + round-trip
kp = e.generate_keypair("mainnet")
env = e.make_envelope("s3cret pw", kp)
check("new envelope is ver:2", env["ver"] == 2)
check("new envelope records iters=600000", env["iters"] == e.PBKDF2_ITERS == 600_000)
check(
    "round-trip decrypt (correct pw)",
    e.decrypt_priv("s3cret pw", env["enc"], env["addr"], env["iters"]) == kp["wif"],
)

# 2. Wrong password must fail (GCM auth tag)
try:
    e.decrypt_priv("wrong pw", env["enc"], env["addr"], env["iters"])
    check("wrong password rejected", False)
except ValueError:
    check("wrong password rejected", True)

# 3. Legacy ver:1 fallback — bundled test image predates the iters field
legacy = HERE / "test_png.png"
if legacy.exists():
    envs = e.read_envelopes(legacy)
    check("legacy test_png.png has an envelope", len(envs) == 1)
    check("legacy envelope has no iters field", "iters" not in envs[0])
    wif = e.decrypt_priv(
        "testpass123", envs[0]["enc"], envs[0]["addr"], envs[0].get("iters", 310_000)
    )
    check("legacy ver:1 decrypts via 310k fallback", wif.startswith("K") or wif.startswith("L"))
else:
    print("  skip legacy test (test_png.png not found)")

# 4. Deterministic seed is stable
a = e.generate_keypair("mainnet", seed_hex="deadbeef")
b = e.generate_keypair("mainnet", seed_hex="deadbeef")
check("seed determinism (addr)", a["addr"] == b["addr"])
check("seed determinism (wif)", a["wif"] == b["wif"])

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
