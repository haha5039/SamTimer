#!/usr/bin/env python3
"""Adapt the tested A56 KernelSU 3.2.5 LKM to the samsung-v2.2 manager key.

Only the certificate SHA-256 literal and the AArch64 certificate length
comparison change. The KDP/RKP/DEFEX hooks and module relocations are retained.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


SOURCE_SHA256 = "9dc6f85e61aa3edfb20db6d65de255607c3753c82223cde467f8bd2a6a703eb2"
OLD_HASH = b"c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6"
NEW_HASH = b"14296df529682e1ada0a4a37f2cab5751f0951706051435394d597168f45dd8b"
PATCH_WORDS = {
    0x5000 + 0x5D58: (0x710CED1F, 0x710C311F),  # cmp w8, #0x33b -> #0x30c
    0x5000 + 0x5D90: (0x52806762, 0x52806182),  # mov w2, #0x33b -> #0x30c
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    raw = args.source.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        parser.error("source module identity differs from the audited A56 build")
    if raw.count(OLD_HASH) != 1 or NEW_HASH in raw:
        parser.error("manager certificate literal is not unique")
    if len(OLD_HASH) != len(NEW_HASH):
        parser.error("certificate literal sizes differ")
    for file_offset, (old_word, _) in PATCH_WORDS.items():
        if raw[file_offset:file_offset + 4] != struct.pack("<I", old_word):
            parser.error(f"certificate length instruction mismatch at 0x{file_offset:x}")

    patched = bytearray(raw)
    hash_offset = raw.index(OLD_HASH)
    patched[hash_offset:hash_offset + len(NEW_HASH)] = NEW_HASH
    for file_offset, (_, new_word) in PATCH_WORDS.items():
        patched[file_offset:file_offset + 4] = struct.pack("<I", new_word)
    if len(patched) != len(raw):
        parser.error("patched module size changed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"source sha256: {SOURCE_SHA256}")
    print(f"patched sha256: {hashlib.sha256(patched).hexdigest()}")
    print("changed offsets: " + ", ".join(
        f"0x{offset:x}" for offset in (hash_offset, *PATCH_WORDS)
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
