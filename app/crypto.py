from __future__ import annotations

import json
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class FieldCipher:
    """AES-256-GCM para o livro-razão e para textos de SLA e mediação."""

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("a chave AES-256 precisa de 32 bytes")
        self._aes = AESGCM(key)

    def encrypt(self, value: Any) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        ciphertext = self._aes.encrypt(nonce, canonical(value).encode("utf-8"), None)
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> Any:
        raw = self._aes.decrypt(nonce, ciphertext, None)
        return json.loads(raw.decode("utf-8"))
