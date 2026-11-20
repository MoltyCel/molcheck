"""The adapter's own Ed25519 key: signs the evidence items in each receipt.

This key is separate from the CDP key. It belongs to whoever runs the adapter, and its public
half goes into the trust list that verifiers pin.
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Dict, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def generate(path: str) -> None:
    if os.path.exists(path):
        raise FileExistsError(f"{path} exists; refusing to overwrite a signing key")
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(pem)


def load(path: str) -> Ed25519PrivateKey:
    with open(path, "rb") as handle:
        key = serialization.load_pem_private_key(handle.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("signing key is not Ed25519")
    return key


def public_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(key.public_key().public_bytes_raw()).decode("ascii")


def keyid(key: Ed25519PrivateKey) -> str:
    return "ed25519:" + hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest()[:16]


def default_source_id(key: Ed25519PrivateKey) -> str:
    return "molcheck-coinbase:" + keyid(key)


def trust_list(key: Ed25519PrivateKey, source_id: str) -> Dict:
    return {"trust_list_version": 1, "sources": {source_id: {"keys": [{
        "algorithm": "ed25519", "keyid": keyid(key), "public_key": public_b64(key)}]}}}


def signer(key: Ed25519PrivateKey) -> Tuple:
    return key.sign, keyid(key)
