#!/usr/bin/env python3
"""
ridi_macos_extract.py — personal DRM-free backup of your own RIDI books (macOS).

SCOPE / STATUS
--------------
This targets the legacy / community-documented RIDI *desktop* (Electron) DRM
where the device key derives from `com.ridibooks.Ridibooks.plist`
(cf. disjukr/ridi-drm-remover). It does NOT cover RIDI's current DRM as
shipped in the Mac App Store iOS build (`/Applications/RIDI.app/Wrapper/`),
which uses a native AES-128-CBC scheme keyed off a device UUID + per-book
`.dat`. Reproducing that would mean reverse-engineering a live commercial
protection (the public successor tools are DMCA-removed) and is intentionally
out of scope.

For the supported case: run it on the same Mac where the RIDI desktop app is
installed and you are logged in (the device key lives in your login data).
Only your own purchased library is touched. Output goes to ./ridi-decrypted/.

    python3 ridi_macos_extract.py            # auto-detect everything
    python3 ridi_macos_extract.py --list     # just list found books
    python3 ridi_macos_extract.py --library /path/to/library --device-id <uuid>

No third-party packages required (uses stdlib + the system `openssl`).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import os
import plistlib
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

HOME = Path.home()
PLIST = HOME / "Library/Preferences/com.ridibooks.Ridibooks.plist"
LIBRARY_CANDIDATES = [
    HOME / "Library/Application Support/Ridibooks/library",
    HOME / "Library/Application Support/RIDI/Ridibooks",
]
SIMPLECRYPT_KEY = "0c2f1bb4acb9f023"  # Qt SimpleCrypt key the app uses for device.device_id


# --------------------------------------------------------------------------- #
# Qt SimpleCrypt (the obfuscation RIDI wraps the stored device id with)
# --------------------------------------------------------------------------- #
class SimpleCrypt:
    def __init__(self, hex_key: str) -> None:
        pairs = [int(hex_key[i : i + 2], 16) for i in range(0, len(hex_key), 2)]
        self.parts = list(reversed(pairs))

    def decrypt(self, data: bytes) -> bytes:
        ct = data[2:]  # strip Qt header (version + flags byte)
        out = bytearray(len(ct))
        last = 0
        for i, c in enumerate(ct):
            out[i] = c ^ last ^ self.parts[i % len(self.parts)]
            last = c
        return bytes(out[1:])[2:]  # drop 1 random byte, then 2-byte length prefix


def get_device_id(explicit: str | None) -> str:
    if explicit:
        return explicit.strip()
    if not PLIST.exists():
        sys.exit(
            f"Could not find {PLIST}\n"
            "Open the RIDI desktop app and log in at least once, or pass "
            "--device-id <uuid> explicitly."
        )
    with open(PLIST, "rb") as fh:
        pl = plistlib.load(fh)
    raw = pl.get("device.device_id") or pl.get("device_id")
    if raw is None:
        sys.exit("device.device_id not present in the RIDI plist; pass --device-id.")
    if isinstance(raw, str):
        raw = base64.b64decode(raw)
    dev = SimpleCrypt(SIMPLECRYPT_KEY).decrypt(raw).decode("latin1").strip("\x00").strip()
    if len(dev) < 18:
        sys.exit(f"Decoded device id looks wrong: {dev!r}")
    return dev


# --------------------------------------------------------------------------- #
# AES-128-ECB (no padding) via the system openssl binary
# --------------------------------------------------------------------------- #
def aes_ecb_decrypt(key: bytes, blob: bytes) -> bytes:
    if len(blob) % 16:
        blob = blob[: len(blob) - (len(blob) % 16)]
    if not blob:
        return b""
    p = subprocess.run(
        ["openssl", "enc", "-d", "-aes-128-ecb", "-nopad", "-K", key.hex()],
        input=blob,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True,
    )
    return p.stdout


def strip_pad(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:  # PKCS#7
        return data[:-n]
    last = data[-1:]  # RIDI also right-pads with a repeated byte
    i = len(data)
    while i > 0 and data[i - 1 : i] == last:
        i -= 1
    if 0 < len(data) - i <= 16:
        return data[:i]
    return data


# --------------------------------------------------------------------------- #
# v11 container: a real ZIP whose entries are wrapped as
#   [flag:1][size:2 LE][~size:2 LE][payload]
# flag==1  -> whole payload is AES-128-ECB encrypted; size == payload length.
# flag==0  -> only the first (size & ~0xF) bytes are encrypted (16 KiB in
#             practice); the remaining tail is stored in clear.
# Decryption is verified at runtime: the result must be valid UTF-8 / a JPEG.
# --------------------------------------------------------------------------- #
TEXTUAL = (".xhtml", ".html", ".htm", ".xml", ".opf", ".ncx", ".css", ".svg")


def _looks_text(b: bytes) -> bool:
    try:
        b.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def decrypt_entry(name: str, payload: bytes, flag: int, size: int, key: bytes) -> bytes:
    if flag == 1:
        return strip_pad(aes_ecb_decrypt(key, payload[:size]))

    # flag == 0 : encrypted prefix + plaintext tail.
    n = (size & ~0xF) or 16384
    n = min(n, len(payload) - (len(payload) % 16))
    head = aes_ecb_decrypt(key, payload[:n])
    result = head + payload[n:]

    # Sanity-check the documented boundary; if it is off, locate it by the
    # ciphertext->plaintext transition (ECB is block-independent, so one
    # decrypt of the whole payload is enough to test any 16-aligned split).
    ok = _looks_text(result) if name.lower().endswith(TEXTUAL) else (
        head[:2] == b"\xff\xd8" and payload[-2:] == b"\xff\xd9"
    )
    if ok:
        return result
    full = aes_ecb_decrypt(key, payload[: len(payload) - (len(payload) % 16)])
    for p in range(0, len(full) + 1, 16):
        if _looks_text(full[:p]) and _looks_text(payload[p:]) and b"<" in full[:p] + payload[p:]:
            return full[:p] + payload[p:]
    return result


def iter_v11(data: bytes):
    off = 0
    while data[off : off + 4] == b"PK\x03\x04":
        ver, fl, mth, tm, dt, crc, csz, usz, nl, el = struct.unpack(
            "<HHHHHIIIHH", data[off + 4 : off + 30]
        )
        name = data[off + 30 : off + 30 + nl].decode("utf-8", "replace")
        body = data[off + 30 + nl + el : off + 30 + nl + el + csz]
        flag = body[0]
        size = struct.unpack("<H", body[1:3])[0]
        guard = struct.unpack("<H", body[3:5])[0]
        if (size ^ 0xFFFF) != guard:  # the [~size] integrity field must match
            raise ValueError(f"{name}: bad v11 header guard")
        yield name, body[5:], flag, size
        off += 30 + nl + el + csz


def candidate_keys(device_id: str, dat: bytes | None) -> list[bytes]:
    keys: list[bytes] = []

    def add(b: bytes) -> None:
        if len(b) >= 16 and b[:16] not in keys:
            keys.append(b[:16])

    add(device_id[2:18].encode("latin1"))
    add(device_id[:16].encode("latin1"))
    add(device_id.replace("-", "")[:16].encode("latin1"))
    if dat:  # legacy: content key embedded in <id>.dat at deviceId.len+32
        try:
            ecb = aes_ecb_decrypt(device_id[:16].encode("latin1"), dat)
            off = len(device_id) + 32
            add(ecb[off : off + 16])
        except Exception:
            pass
    return keys


def pick_key(sample: bytes, keys: list[bytes]) -> bytes | None:
    for name, payload, flag, size in iter_v11(sample):
        if not name.lower().endswith(TEXTUAL):
            continue
        for k in keys:
            try:
                out = decrypt_entry(name, payload, flag, size, k)
            except Exception:
                continue
            if _looks_text(out) and (b"<?xml" in out[:64] or b"<" in out[:8]):
                return k
        return None
    return None


# --------------------------------------------------------------------------- #
# Book discovery / extraction
# --------------------------------------------------------------------------- #
def find_books(library: Path):
    """Yield (book_id, book_dir, source_file, kind)."""
    for user_dir in sorted(p for p in library.iterdir() if p.is_dir()):
        for book_dir in sorted(p for p in user_dir.iterdir() if p.is_dir()):
            bid = book_dir.name
            v11 = book_dir / f"{bid}.v11.epub"
            epub = book_dir / f"{bid}.epub"
            pdf = book_dir / f"{bid}.pdf"
            if v11.exists():
                yield bid, book_dir, v11, "v11"
            elif epub.exists():
                yield bid, book_dir, epub, "epub"
            elif pdf.exists():
                yield bid, book_dir, pdf, "pdf"


def write_epub(entries: list[tuple[str, bytes]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w") as z:
        for name, content in entries:
            if name == "mimetype":
                z.writestr("mimetype", content, compress_type=zipfile.ZIP_STORED)
        for name, content in entries:
            if name == "mimetype":
                continue
            z.writestr(name, content, compress_type=zipfile.ZIP_DEFLATED)


def extract_v11(src: Path, key: bytes, out_path: Path) -> None:
    data = src.read_bytes()
    entries = [
        (name, decrypt_entry(name, payload, flag, size, key))
        for name, payload, flag, size in iter_v11(data)
    ]
    write_epub(entries, out_path)


def extract_simple(src: Path, dat: Path | None, device_id: str, kind: str, out_path: Path) -> None:
    blob = src.read_bytes()
    if dat and dat.exists():  # legacy epub/pdf: per-book content key from <id>.dat
        ecb = aes_ecb_decrypt(device_id[:16].encode("latin1"), dat.read_bytes())
        off = len(device_id) + 32
        content_key = ecb[off : off + 16]
    else:
        content_key = device_id[2:18].encode("latin1")
    out = aes_ecb_decrypt(content_key, blob)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(strip_pad(out) if kind == "pdf" else out)


def main() -> None:
    ap = argparse.ArgumentParser(description="Personal DRM-free backup of your RIDI library (macOS).")
    ap.add_argument("--library", type=Path, help="override RIDI library directory")
    ap.add_argument("--device-id", help="override device id (UUID)")
    ap.add_argument("--out", type=Path, default=Path("ridi-decrypted"))
    ap.add_argument("--list", action="store_true", help="only list discovered books")
    args = ap.parse_args()

    library = args.library
    if library is None:
        for c in LIBRARY_CANDIDATES:
            if c.exists():
                library = c
                break
    if library is None or not library.exists():
        sys.exit(
            "RIDI library not found. Open the desktop app, download your books, "
            "then re-run (or pass --library)."
        )

    books = list(find_books(library))
    if not books:
        sys.exit(f"No books found under {library}")

    print(f"Library: {library}")
    for bid, _d, src, kind in books:
        print(f"  [{kind:4}] {bid}  ({src.name})")
    if args.list:
        return

    device_id = get_device_id(args.device_id)
    print(f"Device id: {device_id}")

    key = None
    for bid, bdir, src, kind in books:  # auto-pick the working v11 entry key once
        if kind == "v11":
            key = pick_key(src.read_bytes(), candidate_keys(device_id, (bdir / f"{bid}.dat").read_bytes() if (bdir / f"{bid}.dat").exists() else None))
            if key:
                print(f"Using entry key derived from device id (len {len(key)}).")
            break

    ok = 0
    for bid, bdir, src, kind in books:
        out = args.out / f"{bid}.{'pdf' if kind == 'pdf' else 'epub'}"
        try:
            if kind == "v11":
                if key is None:
                    print(f"  ! {bid}: could not determine decryption key — skipped")
                    continue
                extract_v11(src, key, out)
            else:
                dat = bdir / f"{bid}.dat"
                extract_simple(src, dat, device_id, kind, out)
            print(f"  ✓ {bid} -> {out}")
            ok += 1
        except Exception as e:  # keep going on a single bad book
            print(f"  ! {bid}: {type(e).__name__}: {e}")

    print(f"\nDone: {ok}/{len(books)} book(s) written to {args.out}/")
    if ok < len(books):
        print("If some books failed, run again and share the messages above.")


if __name__ == "__main__":
    main()
