# BTC Envelope

Embed encrypted Bitcoin private-key envelopes into **official image metadata** and recover them with a beautiful offline-friendly web app.

## What you get

| File | Purpose |
|------|---------|
| `embed_tool.py` | CLI to generate P2WPKH keys and embed encrypted envelopes into image metadata |
| `embed.html` | **Standalone web app** — generate keys & embed into PNG (same crypto as the CLI) |
| `index.html` | **Standalone web app** — recover: drop image → balances → unlock WIF with password |
| `test_*.png/jpg/gif/heic/webp/tiff` | Sample images already containing one encrypted envelope (password: `testpass123`) |
| `testnet/` · `regtest/` | Same apps & CLI, defaulting to those networks |

## Supported formats & official fields

| Format | Field used | Browser support in `index.html` |
|--------|------------|---------------------------------|
| **PNG**  | tEXt chunk `btc-envelopes` | ✅ |
| **JPEG** | EXIF UserComment (UNICODE) | ✅ |
| **GIF**  | Comment Extension | ✅ |
| **TIFF** | ImageDescription (tag 270) | ✅ |
| **WebP** | EXIF UserComment (UNICODE) | ❌ (use Python tool) |
| **HEIF / HEIC** | EXIF UserComment | ❌ (use Python tool) |
| **BMP**  | *not supported* – no standard text metadata fields | — |

## Quick start

### 1. Install dependencies

```bash
pip install pillow cryptography ecdsa piexif pillow-heif
```

### 2. Generate + embed

```bash
# PNG (recommended)
python3 embed_tool.py embed -i photo.png  -o gift.png  -p 'your strong password' -n 2

# JPEG / WebP / TIFF / GIF / HEIF
python3 embed_tool.py embed -i photo.jpg  -o gift.jpg  -p 'pass' -n 1
python3 embed_tool.py embed -i photo.webp -o gift.webp -p 'pass' -n 1
python3 embed_tool.py embed -i photo.tiff -o gift.tiff -p 'pass' -n 1
python3 embed_tool.py embed -i photo.gif  -o gift.gif  -p 'pass' -n 1
python3 embed_tool.py embed -i photo.heic -o gift.heic -p 'pass' -n 1
```

### 3. Web apps (standalone, no server)

Both pages are single self-contained HTML files (no external scripts).

**Generate & embed** — open `embed.html`:
- Choose network, optional extra entropy / seed
- Set a password
- Optionally drop a carrier PNG (or a blank one is created)
- **Generate & embed** → download `btc_envelope.png`
- Works with the Recover page and with `embed_tool.py extract`

**Recover** — open `index.html`:
- Drop the image → addresses + live balances appear immediately
- Click **Unlock private key** → enter the password → WIF is shown
- Import the WIF into Electrum / Sparrow / BlueWallet to spend

Browser embedding writes **PNG** metadata only. For JPEG / GIF / TIFF / WebP / HEIF use the Python CLI.

## Encryption (identical in Python & browser)

- Password → PBKDF2-HMAC-SHA256 (600 000 iterations, 16-byte salt) → 32-byte AES key
- AES-256-GCM (12-byte nonce)
- Additional authenticated data = the Bitcoin address
- Stored as base64(salt ‖ nonce ‖ ciphertext+tag)

## Envelope JSON (stored in the metadata field)

```json
[
  {
    "addr": "bc1q…",
    "enc": "base64…",
    "ver": 1
  }
]
```

Addresses stay public so balances can be shown without the password.  
Only the private key (compressed WIF) is encrypted.

## Test images

| File | Format | Password |
|------|--------|----------|
| `test_png.png`  | PNG  | `testpass123` |
| `test_jpg.jpg`  | JPEG | `testpass123` |
| `test_gif.gif`  | GIF  | `testpass123` |
| `test_tiff.tiff`| TIFF | `testpass123` |
| `test_heic.heic`| HEIF | `testpass123` |
| `test_webp.webp`| WebP | `testpass123` |

```bash
python3 embed_tool.py list test_jpg.jpg
python3 embed_tool.py extract test_jpg.jpg -p testpass123
```

## CLI reference

```
python3 embed_tool.py generate [-n N] [--network mainnet|testnet|regtest] [--extra STRING] [--seed HEX]
python3 embed_tool.py embed -i IMG -o OUT -p PASS [-n N] [--network ...] [--extra ...] [--seed ...] [--keep]
python3 embed_tool.py list IMG
python3 embed_tool.py extract IMG -p PASS
```

## Network variants

| Folder | Default network | Address prefix | Explorer |
|--------|-----------------|----------------|----------|
| (root) | mainnet | `bc1q…` | mempool.space |
| `testnet/` | testnet | `tb1q…` | mempool.space/testnet |
| `regtest/` | regtest | `bcrt1q…` | none (local only) |

Each folder contains its own `embed_tool.py` (default network already set) and `index.html`.

## Encryption vs gpg / age

The tool uses its own scheme (PBKDF2-HMAC-SHA256 + AES-256-GCM).  
It is **not** compatible with `gpg` or `age` out of the box.

If you want to use age/gpg instead you would need to:

1. Change the Python tool to encrypt the WIF with `age -p` or `gpg -c` and store the resulting ciphertext in the metadata field.
2. Change the web app to either:
   - call out to a WASM build of age/gpg (large, non-trivial), or
   - only support extraction via the Python CLI / terminal (`age -d` / `gpg -d`).

The current design prioritises a fully browser-based unlock with no external tools.

## Security notes

- Use a strong, unique password. There is no recovery if forgotten.
- Many social networks and messaging apps strip or re-encode metadata. Prefer sending the file as a document/attachment.
- The private key never leaves your browser / machine.
- This is a convenience tool for physical / offline gift scenarios, not a replacement for proper cold storage.

## Google Sites / static hosting

`index.html` is completely self-contained (no external scripts).  
You can embed the whole file via Google Sites “Embed code” or host it on any static file host.
Only the optional balance lookup calls `https://mempool.space` (or the testnet equivalent).
