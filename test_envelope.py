#!/usr/bin/env python3
"""Round-trip and regression tests for the envelope crypto.

Run:  python3 test_envelope.py
Requires the same deps as embed_tool.py (pillow cryptography ecdsa piexif).

Covers:
  * PBKDF2 iteration count is 600k
  * new envelopes are ver:1 with no iters field
  * new envelopes encrypt/decrypt round-trip
  * wrong password fails (GCM auth)
  * the bundled test_png.png decrypts with the documented password
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


# 1. Iteration count
check("PBKDF2 iterations are 600000", e.PBKDF2_ITERS == 600_000)

# 2. New envelope shape + round-trip
kp = e.generate_keypair("mainnet")
env = e.make_envelope("s3cret pw", kp)
check("new envelope is ver:1", env["ver"] == 1)
check("new envelope has no iters field", "iters" not in env)
check(
    "round-trip decrypt (correct pw)",
    e.decrypt_priv("s3cret pw", env["enc"], env["addr"]) == kp["wif"],
)

# 3. Wrong password must fail (GCM auth tag)
try:
    e.decrypt_priv("wrong pw", env["enc"], env["addr"])
    check("wrong password rejected", False)
except ValueError:
    check("wrong password rejected", True)

# 4. Bundled sample image decrypts with the documented password
sample = HERE / "test_png.png"
if sample.exists():
    envs = e.read_envelopes(sample)
    check("test_png.png has one envelope", len(envs) == 1)
    wif = e.decrypt_priv("testpass123", envs[0]["enc"], envs[0]["addr"])
    check("test_png.png decrypts with testpass123", wif[0] in "KL")
else:
    print("  skip sample test (test_png.png not found)")

# 5. Deterministic seed is stable
a = e.generate_keypair("mainnet", seed_hex="deadbeef")
b = e.generate_keypair("mainnet", seed_hex="deadbeef")
check("seed determinism (addr)", a["addr"] == b["addr"])
check("seed determinism (wif)", a["wif"] == b["wif"])

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
