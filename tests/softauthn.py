"""A software WebAuthn authenticator (P-256 / ES256) for tests and the live end-to-end script.

It produces exactly what a browser hands the server: a `fmt: none` attestationObject and
clientDataJSON for registration, and authenticatorData (UP|UV) + clientDataJSON + an ES256
DER signature for assertions, so the server's real py_webauthn verification runs unmodified.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_AT = 0x40


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SoftAuthenticator:
    def __init__(self, rp_id: str, origin: str):
        self.rp_id = rp_id
        self.origin = origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)
        self.sign_count = 0
        self.user_handle: bytes | None = None

    # -------------------------------------------------------------- helpers

    def _rp_hash(self) -> bytes:
        return hashlib.sha256(self.rp_id.encode()).digest()

    def _cose_key(self) -> bytes:
        nums = self.key.public_key().public_numbers()
        return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})

    def _client_data(self, typ: str, challenge_b64: str, origin: str | None = None) -> bytes:
        return json.dumps({"type": typ, "challenge": challenge_b64, "origin": origin or self.origin,
                           "crossOrigin": False}, separators=(",", ":")).encode()

    # --------------------------------------------------------- registration

    def register(self, options: dict, *, flags: int = FLAG_UP | FLAG_UV | FLAG_AT) -> dict:
        assert options["rp"]["id"] == self.rp_id
        self.user_handle = b64url_decode(options["user"]["id"])
        client_data = self._client_data("webauthn.create", options["challenge"])
        attested = b"\x00" * 16 + struct.pack(">H", len(self.credential_id)) + self.credential_id + self._cose_key()
        auth_data = self._rp_hash() + bytes([flags]) + struct.pack(">I", self.sign_count) + attested
        att_obj = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cid = b64url(self.credential_id)
        return {
            "id": cid, "rawId": cid, "type": "public-key", "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
            "response": {"clientDataJSON": b64url(client_data), "attestationObject": b64url(att_obj),
                         "transports": ["internal"]},
        }

    # ------------------------------------------------------------ assertion

    def assert_(self, options: dict, *, flags: int = FLAG_UP | FLAG_UV, origin: str | None = None,
                challenge_override: str | None = None) -> dict:
        allowed = {c["id"] for c in options.get("allowCredentials", [])}
        assert b64url(self.credential_id) in allowed, "credential not offered by the server"
        self.sign_count += 1
        client_data = self._client_data("webauthn.get", challenge_override or options["challenge"], origin)
        auth_data = self._rp_hash() + bytes([flags]) + struct.pack(">I", self.sign_count)
        signature = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        cid = b64url(self.credential_id)
        return {
            "id": cid, "rawId": cid, "type": "public-key", "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
            "response": {"authenticatorData": b64url(auth_data), "clientDataJSON": b64url(client_data),
                         "signature": b64url(signature),
                         "userHandle": b64url(self.user_handle) if self.user_handle else None},
        }
