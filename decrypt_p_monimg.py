#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import struct

HEADER_FMT = '<II'
HEADER_SIZE = struct.calcsize(HEADER_FMT)
EXPECTED_VERSION = 1


def decrypt_blob(blob: bytes) -> bytes:
    if len(blob) < HEADER_SIZE:
        raise ValueError('Arquivo muito curto para conter cabeçalho.')

    version, stored_size = struct.unpack(HEADER_FMT, blob[:HEADER_SIZE])
    encrypted_payload = blob[HEADER_SIZE:]

    if version != EXPECTED_VERSION:
        raise ValueError(f'Versão inesperada no cabeçalho: {version} (esperado {EXPECTED_VERSION}).')

    if stored_size != len(encrypted_payload) - 4:
        raise ValueError(
            f'Tamanho no cabeçalho inconsistente: {stored_size} (esperado {len(encrypted_payload) - 4}).'
        )

    return bytes((~b) & 0xFF for b in encrypted_payload)


def main() -> None:
    parser = argparse.ArgumentParser(description='Descriptografa p_monimg.bin para texto puro.')
    parser.add_argument('input_file', type=Path, help='Arquivo .bin criptografado')
    parser.add_argument('output_file', type=Path, help='Arquivo de saída descriptografado')
    args = parser.parse_args()

    data = args.input_file.read_bytes()
    decrypted = decrypt_blob(data)
    args.output_file.write_bytes(decrypted)


if __name__ == '__main__':
    main()
