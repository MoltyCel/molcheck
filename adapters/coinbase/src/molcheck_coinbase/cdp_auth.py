"""CDP API key loading and per-request ES256 JWTs for the Coinbase Advanced Trade API.

Coinbase documents: header `alg=ES256`, `kid=<key name>`, `nonce=<random hex>`; claims
`sub=<key name>`, `iss="cdp"`, `nbf=now`, `exp=now+120`, and `uri="<METHOD> <host><path>"`
without scheme and without query string. One JWT per request.

The private key is held in memory only. Nothing in this module prints, logs or returns it.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

API_HOST = "api.coinbase.com"


class KeyLoadError(Exception):
    """The CDP key could not be loaded. The message never contains key material."""


@dataclass(frozen=True)
class CdpKey:
    name: str
    _private: ec.EllipticCurvePrivateKey = field(repr=False)

    def __repr__(self) -> str:  # never show key material
        return f"CdpKey(name={self.name!r})"


def load_key(path: str | None = None) -> CdpKey:
    """Load from the JSON file the CDP portal downloads ({"name", "privateKey"}), or from
    CDP_API_KEY_NAME / CDP_API_KEY_PRIVATE_KEY when no path is given."""
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                blob = json.load(handle)
        except (OSError, ValueError) as exc:
            raise KeyLoadError(f"cannot read key file: {type(exc).__name__}") from None
        name = blob.get("name") or blob.get("id")
        pem = blob.get("privateKey")
    else:
        name = os.environ.get("CDP_API_KEY_NAME")
        pem = os.environ.get("CDP_API_KEY_PRIVATE_KEY")
    if not name or not pem:
        raise KeyLoadError("key name or private key missing")
    pem = pem.replace("\\n", "\n").encode("utf-8")
    try:
        private = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError):
        raise KeyLoadError("private key is not a PEM key; select ECDSA (ES256) in the CDP "
                           "portal, Ed25519 keys are not accepted by this API") from None
    if not isinstance(private, ec.EllipticCurvePrivateKey) or private.curve.name != "secp256r1":
        raise KeyLoadError("private key is not an ECDSA P-256 key")
    return CdpKey(name=name, _private=private)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def build_jwt(key: CdpKey, method: str, path: str, now: int | None = None) -> str:
    now = int(time.time()) if now is None else now
    header = {"alg": "ES256", "kid": key.name, "nonce": secrets.token_hex(16), "typ": "JWT"}
    claims = {"sub": key.name, "iss": "cdp", "nbf": now, "exp": now + 120,
              "uri": f"{method.upper()} {API_HOST}{path}"}
    signing_input = (_b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
                     _b64url(json.dumps(claims, separators=(",", ":")).encode()))
    der = key._private.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return signing_input + "." + _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
