# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

**Coinceal** — a tool for embedding encrypted Bitcoin private-key "envelopes" into official image metadata fields, with two independent implementations of the same crypto. The brand name is used everywhere: CLI filename (`coinceal.py`), page titles, README, EXIF ImageDescription label, download filename (`coinceal.png`), and the PNG tEXt key `coinceal` (`META_KEY` — part of the data format; renaming it orphans previously embedded images). The project was historically named `btc_envelope`; nothing uses that name anymore.

- `coinceal.py` — Python CLI: generate P2WPKH keys, encrypt, embed/extract across PNG/JPEG/GIF/TIFF/WebP/HEIF.
- `embed.html` — standalone browser app: generate keys and embed into PNG, JPEG, or GIF.
- `index.html` — standalone browser app: recover (parse metadata, show balances via mempool.space, decrypt WIF with password).

There is no build system, package manager config, or test suite.

## Commands

```bash
# Python dependencies (no requirements.txt exists)
pip install pillow cryptography ecdsa piexif pillow-heif

# Smoke-test round trip against the bundled test images (password: testpass123)
python3 coinceal.py list test_png.png
python3 coinceal.py extract test_png.png -p testpass123

# Regression tests (envelope shape, round-trip, wrong-pw, seed determinism)
python3 test_envelope.py

# Full CLI
python3 coinceal.py generate [-n N] [--network mainnet|testnet|regtest] [--extra STR] [--seed HEX]
python3 coinceal.py embed -i IMG -o OUT -p PASS [-n N] [--wif WIF --addr ADDR] [--keep]
```

The web apps run by opening the HTML file directly in a browser — no server. Note: Web Crypto (`crypto.subtle`) works on `file://` URLs, but if a change requires a secure context beyond that, serve with `python3 -m http.server`.

## Critical invariant: crypto must match everywhere

The encryption scheme is implemented **twice** (Python `cryptography` lib and browser Web Crypto API) and must stay byte-compatible, or images embedded by one tool become unrecoverable by the other:

- Password → PBKDF2-HMAC-SHA256, **600,000 iterations** (hardcoded `PBKDF2_ITERS`), 16-byte salt → 32-byte AES key
- AES-256-GCM, 12-byte nonce, **AAD = the Bitcoin address string** (binds ciphertext to its address)
- Stored blob: `base64(salt ‖ nonce ‖ ciphertext+tag)`
- Envelope JSON (a top-level array): `[{"addr": "bc1q…", "enc": "base64…", "ver": 1}]`

The iteration count is a fixed constant on both sides — there is no per-envelope `iters` field and no backward-compat fallback. Changing `PBKDF2_ITERS` makes previously-created images undecryptable, so any change to it means regenerating the bundled `test_*` images (`python3 coinceal.py embed -i <img> -o <img> -p testpass123 -n 1`). The `ver` field is reserved for future schema changes but is currently always `1`.

Any change to iterations, salt/nonce sizes, AAD, blob layout, or envelope schema must be made in `coinceal.py`, `embed.html`, `index.html`, **and** all copies in `testnet/` and `regtest/`, then cross-verified: a Python-made envelope must decrypt in the browser and vice-versa. `test_envelope.py` covers the Python round-trip.

### Private-key scalar selection (must match between CLI and browser)

Both `coinceal.py` and `embed.html` pick the secp256k1 scalar the same way, and this must stay in sync (an identical seed must yield an identical address on both):

- **Random keys** use **rejection sampling** — redraw 32 CSPRNG bytes until the value is strictly in `[1, n-1]`. This has zero modulo bias; do not "fix up" an out-of-range draw by reducing mod `n`.
- **Deterministic seeds** (`--seed` / seed field) are `SHA-256(seed)` then reduced **mod n** (with `0 → 1`). Reduction is acceptable *only* here because a fixed input can't be resampled.

## Untrusted input: escape envelope fields in the recovery UI

`index.html` parses envelope JSON out of an **attacker-supplied image** and renders `addr`/`wif` into the DOM. These must be escaped (`escapeHtml()` for text, `encodeURIComponent()` for URLs) — never interpolated raw into `innerHTML` — or a crafted image is a stored-XSS vector on a page that handles private keys. `embed.html` renders only locally generated values and is not exposed to this.

## Metadata fields per format

| Format | Field | Read in browser (`index.html`) | Write in browser (`embed.html`) |
|--------|-------|-------------------------------|--------------------------------|
| PNG | tEXt chunk keyed `coinceal` (`META_KEY`) | ✅ | ✅ |
| JPEG | EXIF UserComment (UNICODE marker + UTF-16LE) | ✅ | ✅ |
| GIF | Comment Extension | ✅ | ✅ |
| TIFF | ImageDescription (tag 270) | ✅ | ❌ |
| WebP / HEIF | EXIF UserComment | ❌ (Python CLI only) | ❌ |
| BMP | unsupported — no standard text field | — | — |

`index.html` contains hand-written binary parsers for each format (`extractPngTextChunks`, `extractJpegUserComment`, `extractGifComment`, `extractTiffImageDescription`); `embed.html` contains hand-written writers (PNG tEXt with CRC, JPEG EXIF, GIF Comment Extension) and its own compact BigInt secp256k1 + bech32 implementation. These pure-JS implementations exist because of the self-containment constraint below.

Browser writer behavior (all lossless — pixel/frame data is never re-encoded):

- **JPEG** (`injectJpegExif`): **preserves existing EXIF** (same policy as the CLI's piexif path). The TIFF structure — IFD0, Exif, GPS, Interop, thumbnail IFD — is parsed into entries (`parseExifTiff`) and re-serialized with recomputed offsets (`serializeExifTiff`); value bytes are copied verbatim in the **source byte order** (an `MM` file stays big-endian), so nothing is reinterpreted. Only ImageDescription and UserComment are replaced. MakerNote bytes are copied as-is — absolute offsets inside them may go stale, the same tradeoff piexif makes. If the segment would exceed the 64 KB APP1 limit, the embedded thumbnail is dropped first; unparseable EXIF falls back to a fresh minimal block. Other segments (JFIF APP0, XMP, ICC) are kept. The UserComment payload is `UNICODE\0` + UTF-16LE, byte-identical to piexif's output.
- **GIF** (`injectGifComment`): walks the full block grammar (extensions, image descriptors, LZW sub-blocks), copies every frame byte-for-byte — animations, per-frame delays, and the NETSCAPE loop extension survive. Existing Comment Extensions are dropped and ours is inserted first (right after the global color table) so readers that return the first comment see ours; a `GIF87a` header is upgraded to `GIF89a` (extensions require it). The Python CLI re-encodes GIFs through Pillow but likewise preserves animation (`save_all` + per-frame durations + loop when `img.is_animated`).

- **JPEG → PNG conversion** (`jpegToPng`, toggles shown only when a JPEG is loaded): "Convert JPEG → PNG" (default **on**, recommended — envelope moves to the tEXt chunk, which photo apps don't display and EXIF scrubbers don't touch) decodes via canvas (pixel-lossless, same resolution, browser bakes EXIF orientation into the pixels) and embeds via the PNG path. Sub-toggle "Keep photo metadata (EXIF)" (default **off**) copies the source EXIF into a PNG **`eXIf` chunk** (`makePngExifChunk`), with the Orientation tag dropped (now baked into pixels — keeping it would double-rotate) and the thumbnail dropped (PNG viewers preview the image itself). Canvas dimension guard at 16384px/side.

New writers must be cross-verified like the crypto: browser-embedded image → `coinceal.py extract` and → `index.html`, plus a round trip against a real photo with existing EXIF / an animated GIF.

## Self-containment constraint

Both HTML files must remain single self-contained files with **no external scripts/stylesheets**. They are hosted on GitHub Pages, which could serve same-origin scripts — but the single-file property is kept deliberately so users can save one HTML file and run it fully offline/air-gapped. The only permitted network calls are the optional balance/price lookups to `https://mempool.space` (or its testnet path). Do not add CDN dependencies.

## Network variants are drifting copies, not symlinks

`testnet/` and `regtest/` each hold copies of `coinceal.py`, `index.html`, and `embed.html` that differ only in defaults (argparse `--network` default, page titles, explorer URLs, address prefixes `bc1q`/`tb1q`/`bcrt1q`). They are **manually synced and have already drifted** — e.g. the root `index.html` has a USD-price feature the testnet copy lacks. When changing shared logic in a root file, propagate the change to both variant folders (preserving their network defaults), or explicitly note the drift.
