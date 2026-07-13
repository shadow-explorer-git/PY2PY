"""Persistent device identity for authenticated PY2PY handshakes."""

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


IDENTITY_DIR = Path.home() / ".py2py"
IDENTITY_FILE = IDENTITY_DIR / "identity_ed25519.pem"


class DeviceIdentity:
    """Stores a stable Ed25519 signing key for this device."""

    def __init__(self):
        IDENTITY_DIR.mkdir(mode=0o700, exist_ok=True)
        if IDENTITY_FILE.exists():
            self.private_key = serialization.load_pem_private_key(
                IDENTITY_FILE.read_bytes(), password=None
            )
        else:
            self.private_key = Ed25519PrivateKey.generate()
            pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            fd = os.open(IDENTITY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as file:
                file.write(pem)
        try:
            os.chmod(IDENTITY_FILE, 0o600)
        except OSError:
            pass

    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    @staticmethod
    def fingerprint(public_key: bytes) -> str:
        digest = hashlib.sha256(public_key).hexdigest().upper()
        return ":".join(digest[index:index + 2] for index in range(0, 16, 2))
