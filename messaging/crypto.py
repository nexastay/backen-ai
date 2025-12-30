"""Utilities for encrypting / decrypting messaging payloads."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from hashlib import sha256
from typing import Optional

from cryptography.fernet import Fernet


class MessageCipher:
    """Symmetric cipher helper (Fernet) derived from the app secret."""

    def __init__(self, secret: str) -> None:
        key = sha256(secret.encode("utf-8")).digest()
        self._fernet = Fernet(urlsafe_b64encode(key))

    def encrypt(self, content: str) -> str:
        token = self._fernet.encrypt(content.encode("utf-8"))
        return token.decode("utf-8")

    def decrypt(self, payload: str) -> str:
        data = self._fernet.decrypt(payload.encode("utf-8"))
        return data.decode("utf-8")


_default_cipher: Optional[MessageCipher] = None


def get_cipher(secret: str) -> MessageCipher:
    global _default_cipher
    if _default_cipher is None:
        _default_cipher = MessageCipher(secret)
    return _default_cipher
