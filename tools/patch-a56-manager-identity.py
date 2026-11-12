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


SOURCE_SHA256 = "46e0dd2406cf6490535ccb087d911d1342136b628a867aeaba67e5a0404649a7"
OLD_HASH = b"c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6"
NEW_HASH = b"14296df529682e1ada0a4a37f2cab5751f0951706051435394d597168f45dd8b"
OLD_COMPARE = 0x710CEEBF  # cmp w21, #0x33b (827-byte certificate)
NEW_COMPARE = 0x710C32BF  # cmp w21, #0x30c (780-byte certificate)
COMPARE_FILE_OFFSET = 0x5000 + 0x65D8  # .text offset + check_block instruction


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
    old_instruction = struct.pack("<I", OLD_COMPARE)
    if raw[COMPARE_FILE_OFFSET:COMPARE_FILE_OFFSET + 4] != old_instruction:
        parser.error("certificate length comparison is not at the audited offset")

    patched = bytearray(raw)
    hash_offset = raw.index(OLD_HASH)
    patched[hash_offset:hash_offset + len(NEW_HASH)] = NEW_HASH
    patched[COMPARE_FILE_OFFSET:COMPARE_FILE_OFFSET + 4] = struct.pack("<I", NEW_COMPARE)
    if len(patched) != len(raw):
        parser.error("patched module size changed")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(patched)
    print(f"source sha256: {SOURCE_SHA256}")
    print(f"patched sha256: {hashlib.sha256(patched).hexdigest()}")
    print(f"changed offsets: 0x{hash_offset:x}, 0x{COMPARE_FILE_OFFSET:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
