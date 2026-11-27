"""Throwaway SSH host key blobs for tests."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def ed25519_blob() -> str:
    """Base64 body of fresh ssh-ed25519 public key."""

    line = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    return line.decode().split()[1]
