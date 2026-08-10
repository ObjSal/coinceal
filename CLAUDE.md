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

# Full CLI
python3 embed_tool.py generate [-n N] [--network mainnet|testnet|regtest] [--extra STR] [--seed HEX]
python3 embed_tool.py embed -i IMG -o OUT -p PASS [-n N] [--wif WIF --addr ADDR] [--keep]
```

The web apps run by opening the HTML file directly in a browser — no server. Note: Web Crypto (`crypto.subtle`) works on `file://` URLs, but if a change requires a secure context beyond that, serve with `python3 -m http.server`.

## Critical invariant: crypto must match everywhere

The encryption scheme is implemented **twice** (Python `cryptography` lib and browser Web Crypto API) and must stay byte-compatible, or images embedded by one tool become unrecoverable by the other:

- Password → PBKDF2-HMAC-SHA256, **310,000 iterations**, 16-byte salt → 32-byte AES key
- AES-256-GCM, 12-byte nonce, **AAD = the Bitcoin address string** (binds ciphertext to its address)
- Stored blob: `base64(salt ‖ nonce ‖ ciphertext+tag)`
- Envelope JSON (a top-level array): `[{"addr": "bc1q…", "enc": "base64…", "ver": 1}]`

Any change to iterations, salt/nonce sizes, AAD, blob layout, or envelope schema must be made in `embed_tool.py`, `embed.html`, `index.html`, **and** all copies in `testnet/` and `regtest/` (see below). The `ver` field exists for schema evolution.

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
