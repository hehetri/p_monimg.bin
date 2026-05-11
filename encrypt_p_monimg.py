#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import struct

HEADER_FMT = '<II'
EXPECTED_VERSION = 1


def encrypt_blob(plain: bytes) -> bytes:
    encrypted_payload = bytes((~b) & 0xFF for b in plain)
    stored_size = len(encrypted_payload) - 4
    header = struct.pack(HEADER_FMT, EXPECTED_VERSION, stored_size)
    return header + encrypted_payload


def main() -> None:
    parser = argparse.ArgumentParser(description='Criptografa arquivo texto para o formato p_monimg.bin.')
    parser.add_argument('input_file', type=Path, help='Arquivo puro')
    parser.add_argument('output_file', type=Path, help='Arquivo .bin criptografado')
    args = parser.parse_args()

    plain = args.input_file.read_bytes()
    encrypted = encrypt_blob(plain)
    args.output_file.write_bytes(encrypted)


if __name__ == '__main__':
    main()
