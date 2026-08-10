#!/usr/bin/env python3
"""
BTC Envelope Embedder
=====================
Generate single P2WPKH (native SegWit) Bitcoin keypairs and embed encrypted
"envelopes" {address, private_key} into official image metadata fields.

Encryption: PBKDF2-HMAC-SHA256 (310k iterations) + AES-256-GCM
Compatible with the companion web app (same scheme via Web Crypto API).

Supported formats & official fields used:
  PNG   → tEXt chunk named "btc-envelopes"
  JPEG  → EXIF UserComment (UNICODE)
  WEBP  → EXIF UserComment (UNICODE)
  TIFF  → ImageDescription (tag 270)
  HEIF  → EXIF UserComment (UNICODE)   [requires pillow-heif]
  GIF   → Comment Extension
  BMP   → not supported (no standard text metadata fields)

Usage examples:
  python3 embed_tool.py generate
  python3 embed_tool.py embed -i photo.png  -o secret.png  -p 'correct horse battery' -n 2
  python3 embed_tool.py embed -i photo.jpg  -o secret.jpg  -p 'pass' -n 1
  python3 embed_tool.py embed -i photo.heic -o secret.heic -p 'pass' -n 1
  python3 embed_tool.py list secret.png
  python3 embed_tool.py extract secret.png -p 'correct horse battery'
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
try:
    from PIL import Image, PngImagePlugin
except ImportError:
    print("Pillow required:  pip install pillow", file=sys.stderr)
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("cryptography required:  pip install cryptography", file=sys.stderr)
    sys.exit(1)

try:
    from ecdsa import SigningKey, SECP256k1
except ImportError:
    print("ecdsa required:  pip install ecdsa", file=sys.stderr)
    sys.exit(1)

try:
    import piexif
except ImportError:
    print("piexif required for JPEG/HEIF:  pip install piexif", file=sys.stderr)
    sys.exit(1)

# HEIF is optional at import time; we register on demand
_heif_registered = False
def _ensure_heif():
    global _heif_registered
    if _heif_registered:
        return
    try:
        from pillow_heif import register_heif_opener
        register_heif_opener()
        _heif_registered = True
    except ImportError:
        print("pillow-heif required for HEIF/HEIC:  pip install pillow-heif", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Base58 / Bech32 (pure)
# ---------------------------------------------------------------------------

B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    res = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        res.append(B58_ALPHABET[r])
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return (B58_ALPHABET[:1] * pad + res[::-1]).decode("ascii")

def b58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum)


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _bech32_polymod(values: list[int]) -> int:
    GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _bech32_create_checksum(hrp: str, data: list[int]) -> list[int]:
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp: str, data: list[int]) -> str:
    combined = data + _bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join(BECH32_CHARSET[d] for d in combined)

def convertbits(data: bytes | list[int], frombits: int, tobits: int, pad: bool = True) -> list[int] | None:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def pubkey_to_p2wpkh(pubkey_compressed: bytes, hrp: str = "bc") -> str:
    sha = hashlib.sha256(pubkey_compressed).digest()
    ripe = hashlib.new("ripemd160", sha).digest()
    data = [0] + convertbits(ripe, 8, 5)  # type: ignore
    return bech32_encode(hrp, data)


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def _normalize_seed_hex(seed_hex: str) -> bytes:
    """Accept hex string (with optional 0x / spaces) and return 32-byte digest."""
    cleaned = seed_hex.strip().lower().replace("0x", "").replace(" ", "")
    if not cleaned or any(c not in "0123456789abcdef" for c in cleaned):
        raise ValueError("Seed must be a hex string (e.g. 64 hex characters for 32 bytes)")
    raw = bytes.fromhex(cleaned)
    # Always hash so any length is safe and we never use the raw seed directly
    return hashlib.sha256(raw).digest()


def generate_keypair(
    network: str = "mainnet",
    extra_entropy: bytes | str | None = None,
    seed_hex: str | None = None,
) -> dict[str, str]:
    """
    Generate a single secp256k1 keypair.

    network: "mainnet" | "testnet" | "regtest"

    Entropy sources (in order of precedence):
      1. seed_hex  – deterministic. The hex is SHA-256'd to 32 bytes and used
                     as the private key material. Protect this seed carefully.
      2. os.urandom(32) mixed with optional extra_entropy via SHA-256.
         Providing extra_entropy is recommended (keyboard mashing, dice, etc.).
    """
    network = network.lower()
    if network not in ("mainnet", "testnet", "regtest"):
        raise ValueError("network must be mainnet, testnet or regtest")

    if seed_hex is not None:
        priv_bytes = _normalize_seed_hex(seed_hex)
    else:
        base = os.urandom(32)
        if extra_entropy is not None:
            if isinstance(extra_entropy, str):
                extra_entropy = extra_entropy.encode("utf-8")
            priv_bytes = hashlib.sha256(base + extra_entropy).digest()
        else:
            priv_bytes = base

    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    priv = sk.to_string()
    vk = sk.get_verifying_key()
    pub = vk.to_string("compressed")

    # WIF version byte: mainnet 0x80, testnet/regtest 0xef
    version = b"\x80" if network == "mainnet" else b"\xef"
    wif = b58check_encode(version + priv + b"\x01")

    hrp = {"mainnet": "bc", "testnet": "tb", "regtest": "bcrt"}[network]
    addr = pubkey_to_p2wpkh(pub, hrp=hrp)

    return {
        "priv_hex": priv.hex(),
        "wif": wif,
        "addr": addr,
        "pubkey_hex": pub.hex(),
        "network": network,
    }


# ---------------------------------------------------------------------------
# Encryption (matches Web Crypto companion)
# ---------------------------------------------------------------------------

PBKDF2_ITERS = 310_000
META_KEY = "btc-envelopes"          # PNG tEXt key
USERCOMMENT_PREFIX = b"UNICODE\x00" # EXIF UserComment charset marker

def encrypt_priv(password: str, wif: str, addr: str) -> str:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    key = kdf.derive(password.encode("utf-8"))
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, wif.encode("utf-8"), addr.encode("utf-8"))
    blob = salt + nonce + ct
    return base64.b64encode(blob).decode("ascii")

def decrypt_priv(password: str, enc_b64: str, addr: str) -> str:
    raw = base64.b64decode(enc_b64)
    if len(raw) < 16 + 12 + 16:
        raise ValueError("Ciphertext too short")
    salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    key = kdf.derive(password.encode("utf-8"))
    aesgcm = AESGCM(key)
    try:
        pt = aesgcm.decrypt(nonce, ct, addr.encode("utf-8"))
    except Exception as e:
        raise ValueError("Decryption failed (wrong password or corrupted data)") from e
    return pt.decode("utf-8")


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------

def make_envelope(password: str, keypair: dict[str, str]) -> dict[str, str]:
    enc = encrypt_priv(password, keypair["wif"], keypair["addr"])
    return {
        "addr": keypair["addr"],
        "enc": enc,
        "ver": 1,
    }

def envelopes_to_json(envelopes: list[dict]) -> str:
    return json.dumps(envelopes, separators=(",", ":"))

def parse_envelopes_json(s: str) -> list[dict]:
    data = json.loads(s)
    if not isinstance(data, list):
        raise ValueError("Expected JSON array of envelopes")
    return data


# ---------------------------------------------------------------------------
# Format detection & metadata read/write (official fields only)
# ---------------------------------------------------------------------------

def _detect_format(path: Path) -> str:
    """Return uppercase format name used by Pillow."""
    suffix = path.suffix.lower()
    mapping = {
        ".png": "PNG",
        ".jpg": "JPEG", ".jpeg": "JPEG",
        ".gif": "GIF",
        ".bmp": "BMP",
        ".heic": "HEIF", ".heif": "HEIF",
        ".hif": "HEIF",
        ".webp": "WEBP",
        ".tif": "TIFF", ".tiff": "TIFF",
    }
    if suffix in mapping:
        return mapping[suffix]
    # Fallback: let Pillow sniff
    try:
        with Image.open(path) as im:
            return (im.format or "UNKNOWN").upper()
    except Exception:
        return "UNKNOWN"


def _exif_usercomment_encode(text: str) -> bytes:
    """EXIF UserComment value: charset marker + UTF-16LE payload."""
    return USERCOMMENT_PREFIX + text.encode("utf-16le")

def _exif_usercomment_decode(raw: bytes) -> str | None:
    if not raw:
        return None
    if raw.startswith(b"UNICODE\x00"):
        return raw[8:].decode("utf-16le", errors="replace")
    if raw.startswith(b"ASCII\x00\x00\x00"):
        return raw[8:].decode("ascii", errors="replace")
    # Some writers omit the marker
    try:
        return raw.decode("utf-8")
    except Exception:
        return None


def read_envelopes(path: Path) -> list[dict]:
    """Extract envelope list from official metadata of the image."""
    fmt = _detect_format(path)

    if fmt == "HEIF":
        _ensure_heif()

    if fmt == "BMP":
        # No usable standard text field
        return []

    try:
        img = Image.open(path)
    except Exception as e:
        raise ValueError(f"Cannot open image: {e}") from e

    raw_json: str | None = None

    if fmt == "PNG":
        # Official tEXt / iTXt
        txt = getattr(img, "text", {}) or {}
        raw_json = txt.get(META_KEY) or img.info.get(META_KEY)

    elif fmt in ("JPEG", "HEIF", "WEBP"):
        exif_bytes = img.info.get("exif")
        if exif_bytes:
            try:
                exif = piexif.load(exif_bytes)
                uc = exif.get("Exif", {}).get(piexif.ExifIFD.UserComment)
                if uc:
                    raw_json = _exif_usercomment_decode(uc)
            except Exception:
                pass
        # Fallback: some tools put data in ImageDescription
        if not raw_json and "exif" in img.info:
            try:
                exif = piexif.load(img.info["exif"])
                desc = exif.get("0th", {}).get(piexif.ImageIFD.ImageDescription)
                if desc:
                    raw_json = desc.decode("utf-8", errors="replace") if isinstance(desc, bytes) else str(desc)
            except Exception:
                pass

    elif fmt == "GIF":
        comment = img.info.get("comment")
        if comment:
            if isinstance(comment, bytes):
                raw_json = comment.decode("utf-8", errors="replace")
            else:
                raw_json = str(comment)

    elif fmt == "TIFF":
        # Official ImageDescription tag (270)
        if hasattr(img, "tag_v2") and 270 in img.tag_v2:
            val = img.tag_v2[270]
            raw_json = val.decode("utf-8", errors="replace") if isinstance(val, bytes) else str(val)
        elif img.info.get("description"):
            raw_json = str(img.info["description"])

    if not raw_json:
        return []

    # Strip possible whitespace / BOM
    raw_json = raw_json.strip().lstrip("\ufeff")
    try:
        return parse_envelopes_json(raw_json)
    except Exception:
        return []


def write_envelopes(src: Path, dst: Path, envelopes: list[dict]) -> None:
    """Write the envelope JSON into the official metadata field of the target format."""
    fmt = _detect_format(src)
    json_str = envelopes_to_json(envelopes)

    if fmt == "HEIF":
        _ensure_heif()

    if fmt == "BMP":
        raise ValueError(
            "BMP has no standard text/metadata fields that can hold arbitrary data.\n"
            "Please use PNG, JPEG, WEBP, TIFF, GIF or HEIF instead."
        )

    img = Image.open(src)
    # Preserve mode / size; convert if needed for some formats
    if img.mode not in ("RGB", "RGBA", "L", "P"):
        img = img.convert("RGB")

    if fmt == "PNG":
        meta = PngImagePlugin.PngInfo()
        # Keep existing text chunks except our key
        if hasattr(img, "text"):
            for k, v in img.text.items():
                if k != META_KEY:
                    meta.add_text(k, v)
        meta.add_text(META_KEY, json_str)
        img.save(dst, "PNG", pnginfo=meta, optimize=True)

    elif fmt in ("JPEG", "WEBP"):
        # Build / merge EXIF with UserComment
        exif_dict: dict[str, Any] = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}
        if "exif" in img.info:
            try:
                exif_dict = piexif.load(img.info["exif"])
            except Exception:
                pass
        for k in ("0th", "Exif"):
            if k not in exif_dict or exif_dict[k] is None:
                exif_dict[k] = {}
        exif_dict["Exif"][piexif.ExifIFD.UserComment] = _exif_usercomment_encode(json_str)
        exif_dict["0th"][piexif.ImageIFD.ImageDescription] = b"BTC Envelope"
        exif_bytes = piexif.dump(exif_dict)
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")
        if fmt == "JPEG":
            img.save(dst, "JPEG", quality=92, exif=exif_bytes)
        else:
            img.save(dst, "WEBP", quality=90, exif=exif_bytes)

    elif fmt == "HEIF":
        exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "thumbnail": None}
        if "exif" in img.info:
            try:
                exif_dict = piexif.load(img.info["exif"])
            except Exception:
                pass
        for k in ("0th", "Exif"):
            if k not in exif_dict or exif_dict[k] is None:
                exif_dict[k] = {}
        exif_dict["Exif"][piexif.ExifIFD.UserComment] = _exif_usercomment_encode(json_str)
        exif_dict["0th"][piexif.ImageIFD.ImageDescription] = b"BTC Envelope"
        exif_bytes = piexif.dump(exif_dict)
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")
        img.save(dst, format="HEIF", exif=exif_bytes, quality=90)

    elif fmt == "GIF":
        # GIF Comment Extension – official place for arbitrary text
        if img.mode not in ("P", "L", "RGB"):
            img = img.convert("P", palette=Image.ADAPTIVE)
        img.save(dst, "GIF", comment=json_str.encode("utf-8"))

    elif fmt == "TIFF":
        # Official ImageDescription tag (270)
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")
        img.save(dst, "TIFF", description=json_str, compression="tiff_deflate")

    else:
        raise ValueError(
            f"Unsupported format '{fmt}'. Supported: PNG, JPEG, WEBP, TIFF, HEIF, GIF.\n"
            "(BMP has no usable standard metadata fields.)"
        )

    print(f"[+] Wrote {len(envelopes)} envelope(s) into {fmt} official metadata → {dst}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_generate(args: argparse.Namespace) -> None:
    if args.seed and args.n > 1:
        print("When using --seed only one key can be generated (-n 1).", file=sys.stderr)
        sys.exit(1)
    for i in range(args.n):
        kp = generate_keypair(
            network=args.network,
            extra_entropy=args.extra,
            seed_hex=args.seed,
        )
        print(f"--- Keypair {i+1} ---")
        print(f"Network : {kp['network']}")
        print(f"Address : {kp['addr']}")
        print(f"WIF     : {kp['wif']}")
        print(f"PrivHex : {kp['priv_hex']}")
        print()


def cmd_embed(args: argparse.Namespace) -> None:
    password = args.password
    if not password:
        import getpass
        password = getpass.getpass("Password to encrypt private keys: ")
        if not password:
            print("Password required", file=sys.stderr)
            sys.exit(1)

    src = Path(args.input)
    if not src.exists():
        print(f"Input not found: {src}", file=sys.stderr)
        sys.exit(1)

    envelopes: list[dict] = []

    if args.keep:
        envelopes = read_envelopes(src)
        print(f"[*] Keeping {len(envelopes)} existing envelope(s)")

    if args.wif:
        if not args.addr:
            print("--addr is required when using --wif", file=sys.stderr)
            sys.exit(1)
        kp = {"wif": args.wif, "addr": args.addr, "priv_hex": "", "pubkey_hex": ""}
        envelopes.append(make_envelope(password, kp))
    else:
        if args.seed and args.n > 1:
            print("When using --seed only one key can be generated (-n 1).", file=sys.stderr)
            sys.exit(1)
        for _ in range(args.n):
            kp = generate_keypair(
                network=args.network,
                extra_entropy=args.extra,
                seed_hex=args.seed,
            )
            envelopes.append(make_envelope(password, kp))
            print(f"[+] Generated {kp['addr']} ({kp['network']})")

    if not envelopes:
        print("Nothing to embed", file=sys.stderr)
        sys.exit(1)

    dst = Path(args.output) if args.output else src.with_name(src.stem + "_env" + src.suffix)

    write_envelopes(src, dst, envelopes)
    print(f"[*] Total envelopes in file: {len(envelopes)}")
    print("[*] Open the companion web app, drop the image, and use the same password to unlock.")


def cmd_list(args: argparse.Namespace) -> None:
    path = Path(args.input)
    envs = read_envelopes(path)
    if not envs:
        print("No envelopes found in official metadata.")
        return
    print(f"Found {len(envs)} envelope(s):\n")
    for i, e in enumerate(envs, 1):
        print(f"  [{i}] {e.get('addr', '?')}")
        print(f"      enc : {e.get('enc', '')[:48]}…")
        print()


def cmd_extract(args: argparse.Namespace) -> None:
    path = Path(args.input)
    envs = read_envelopes(path)
    if not envs:
        print("No envelopes found in official metadata.")
        return

    password = args.password
    if not password:
        import getpass
        password = getpass.getpass("Password: ")

    print(f"Decrypting {len(envs)} envelope(s)…\n")
    for i, e in enumerate(envs, 1):
        addr = e.get("addr", "?")
        enc = e.get("enc")
        if not enc:
            print(f"  [{i}] {addr}  (no encrypted payload)")
            continue
        try:
            wif = decrypt_priv(password, enc, addr)
            print(f"  [{i}] {addr}")
            print(f"      WIF : {wif}")
            print()
        except ValueError as err:
            print(f"  [{i}] {addr}  → FAILED: {err}")
            print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Embed encrypted Bitcoin key envelopes into official image metadata",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_gen = sub.add_parser("generate", help="Generate new P2WPKH keypairs and print them")
    p_gen.add_argument("-n", type=int, default=1, help="Number of keys to generate")
    p_gen.add_argument("--network", choices=["mainnet", "testnet", "regtest"], default="mainnet",
                       help="Bitcoin network (default: mainnet)")
    p_gen.add_argument("--extra", metavar="STRING",
                       help="Extra entropy mixed with os.urandom (recommended). Any string.")
    p_gen.add_argument("--seed", metavar="HEX",
                       help="Deterministic seed (hex). SHA-256'd to 32 bytes. Use -n 1 only.")
    p_gen.set_defaults(func=cmd_generate)

    p_emb = sub.add_parser("embed", help="Generate/encrypt envelopes and embed into image metadata")
    p_emb.add_argument("-i", "--input", required=True, help="Source image")
    p_emb.add_argument("-o", "--output", help="Output image (default: <stem>_env.<ext>)")
    p_emb.add_argument("-p", "--password", help="Encryption password (prompt if omitted)")
    p_emb.add_argument("-n", type=int, default=1, help="How many new keys to generate")
    p_emb.add_argument("--wif", help="Embed an existing WIF instead of generating")
    p_emb.add_argument("--addr", help="Address belonging to --wif (required with --wif)")
    p_emb.add_argument("--keep", action="store_true", help="Keep already present envelopes")
    p_emb.add_argument("--network", choices=["mainnet", "testnet", "regtest"], default="mainnet",
                       help="Bitcoin network (default: mainnet)")
    p_emb.add_argument("--extra", metavar="STRING",
                       help="Extra entropy mixed with os.urandom (recommended). Any string.")
    p_emb.add_argument("--seed", metavar="HEX",
                       help="Deterministic seed (hex). SHA-256'd to 32 bytes. Use -n 1 only.")
    p_emb.set_defaults(func=cmd_embed)

    p_list = sub.add_parser("list", help="Show addresses present in the image (no password)")
    p_list.add_argument("input", help="Image containing envelopes")
    p_list.set_defaults(func=cmd_list)

    p_ext = sub.add_parser("extract", help="Decrypt and print private keys (WIF)")
    p_ext.add_argument("input", help="Image containing envelopes")
    p_ext.add_argument("-p", "--password", help="Password (prompt if omitted)")
    p_ext.set_defaults(func=cmd_extract)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
