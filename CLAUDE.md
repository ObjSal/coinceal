# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A tool for embedding encrypted Bitcoin private-key "envelopes" into official image metadata fields, with two independent implementations of the same crypto:

- `embed_tool.py` — Python CLI: generate P2WPKH keys, encrypt, embed/extract across PNG/JPEG/GIF/TIFF/WebP/HEIF.
- `embed.html` — standalone browser app: generate keys and embed into PNG only.
- `index.html` — standalone browser app: recover (parse metadata, show balances via mempool.space, decrypt WIF with password).

There is no build system, package manager config, or test suite.

## Commands

```bash
# Python dependencies (no requirements.txt exists)
pip install pillow cryptography ecdsa piexif pillow-heif

# Smoke-test round trip against the bundled test images (password: testpass123)
python3 embed_tool.py list test_png.png
python3 embed_tool.py extract test_png.png -p testpass123

# Regression tests (envelope shape, round-trip, wrong-pw, legacy fallback, seed determinism)
python3 test_envelope.py

# Full CLI
python3 embed_tool.py generate [-n N] [--network mainnet|testnet|regtest] [--extra STR] [--seed HEX]
python3 embed_tool.py embed -i IMG -o OUT -p PASS [-n N] [--wif WIF --addr ADDR] [--keep]
```

The web apps run by opening the HTML file directly in a browser — no server. Note: Web Crypto (`crypto.subtle`) works on `file://` URLs, but if a change requires a secure context beyond that, serve with `python3 -m http.server`.

## Critical invariant: crypto must match everywhere

The encryption scheme is implemented **twice** (Python `cryptography` lib and browser Web Crypto API) and must stay byte-compatible, or images embedded by one tool become unrecoverable by the other:

- Password → PBKDF2-HMAC-SHA256, **600,000 iterations** (hardcoded `PBKDF2_ITERS`), 16-byte salt → 32-byte AES key
- AES-256-GCM, 12-byte nonce, **AAD = the Bitcoin address string** (binds ciphertext to its address)
- Stored blob: `base64(salt ‖ nonce ‖ ciphertext+tag)`
- Envelope JSON (a top-level array): `[{"addr": "bc1q…", "enc": "base64…", "ver": 1}]`

The iteration count is a fixed constant on both sides — there is no per-envelope `iters` field and no backward-compat fallback. Changing `PBKDF2_ITERS` makes previously-created images undecryptable, so any change to it means regenerating the bundled `test_*` images (`python3 embed_tool.py embed -i <img> -o <img> -p testpass123 -n 1`). The `ver` field is reserved for future schema changes but is currently always `1`.

Any change to iterations, salt/nonce sizes, AAD, blob layout, or envelope schema must be made in `embed_tool.py`, `embed.html`, `index.html`, **and** all copies in `testnet/` and `regtest/`, then cross-verified: a Python-made envelope must decrypt in the browser and vice-versa. `test_envelope.py` covers the Python round-trip.

### Private-key scalar selection (must match between CLI and browser)

Both `embed_tool.py` and `embed.html` pick the secp256k1 scalar the same way, and this must stay in sync (an identical seed must yield an identical address on both):

- **Random keys** use **rejection sampling** — redraw 32 CSPRNG bytes until the value is strictly in `[1, n-1]`. This has zero modulo bias; do not "fix up" an out-of-range draw by reducing mod `n`.
- **Deterministic seeds** (`--seed` / seed field) are `SHA-256(seed)` then reduced **mod n** (with `0 → 1`). Reduction is acceptable *only* here because a fixed input can't be resampled.

## Untrusted input: escape envelope fields in the recovery UI

`index.html` parses envelope JSON out of an **attacker-supplied image** and renders `addr`/`wif` into the DOM. These must be escaped (`escapeHtml()` for text, `encodeURIComponent()` for URLs) — never interpolated raw into `innerHTML` — or a crafted image is a stored-XSS vector on a page that handles private keys. `embed.html` renders only locally generated values and is not exposed to this.

## Metadata fields per format

| Format | Field | Read in browser (`index.html`) | Write in browser (`embed.html`) |
|--------|-------|-------------------------------|--------------------------------|
| PNG | tEXt chunk keyed `btc-envelopes` (`META_KEY`) | ✅ | ✅ (only format) |
| JPEG | EXIF UserComment (UNICODE marker + UTF-16LE) | ✅ | ❌ |
| GIF | Comment Extension | ✅ | ❌ |
| TIFF | ImageDescription (tag 270) | ✅ | ❌ |
| WebP / HEIF | EXIF UserComment | ❌ (Python CLI only) | ❌ |
| BMP | unsupported — no standard text field | — | — |

`index.html` contains hand-written binary parsers for each format (`extractPngTextChunks`, `extractJpegUserComment`, `extractGifComment`, `extractTiffImageDescription`); `embed.html` contains a PNG tEXt chunk writer with CRC and its own compact BigInt secp256k1 + bech32 implementation. These pure-JS implementations exist because of the self-containment constraint below.

## Self-containment constraint

Both HTML files must remain single self-contained files with **no external scripts/stylesheets** (they are hosted via Google Sites "Embed code" / static hosting). The only permitted network calls are the optional balance/price lookups to `https://mempool.space` (or its testnet path). Do not add CDN dependencies.

## Network variants are drifting copies, not symlinks

`testnet/` and `regtest/` each hold copies of `embed_tool.py`, `index.html`, and `embed.html` that differ only in defaults (argparse `--network` default, page titles, explorer URLs, address prefixes `bc1q`/`tb1q`/`bcrt1q`). They are **manually synced and have already drifted** — e.g. the root `index.html` has a USD-price feature the testnet copy lacks. When changing shared logic in a root file, propagate the change to both variant folders (preserving their network defaults), or explicitly note the drift.
