"""WebAuthn ceremonies (py_webauthn 3.x): passkey registration and decision assertions."""
from __future__ import annotations

import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import decode_credential_public_key, decoded_public_key_to_cryptography
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from .config import Settings

# The algorithms perathos.gate.verify_receipt can check offline.
SUPPORTED_ALGS = [
    COSEAlgorithmIdentifier.ECDSA_SHA_256,  # -7
    COSEAlgorithmIdentifier.EDDSA,  # -8
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,  # -257
]


class WebAuthnError(ValueError):
    """The authenticator response did not verify."""


@dataclass
class RegisteredCredential:
    credential_id: bytes
    public_key_der: bytes
    public_key_cose: bytes
    alg: int
    sign_count: int


def registration_options(settings: Settings, *, user_name: str, user_handle: bytes, challenge: bytes,
                         exclude: list[bytes] | None = None) -> dict:
    opts = generate_registration_options(
        rp_id=settings.rp_id,
        rp_name=settings.rp_name,
        user_name=user_name,
        user_display_name=user_name,
        user_id=user_handle,
        challenge=challenge,
        timeout=120_000,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[PublicKeyCredentialDescriptor(id=c) for c in (exclude or [])],
        supported_pub_key_algs=SUPPORTED_ALGS,
    )
    return json.loads(options_to_json(opts))


def cose_to_der(public_key_cose: bytes) -> tuple[bytes, int]:
    """COSE_Key -> (DER SubjectPublicKeyInfo, COSE alg)."""
    try:
        decoded = decode_credential_public_key(public_key_cose)
    except (WebAuthnException, KeyError, TypeError, ValueError) as exc:
        raise WebAuthnError(f"bad credential public key: {exc}") from exc
    alg = int(decoded.alg)
    if alg not in (-7, -8, -257):
        raise WebAuthnError(f"unsupported passkey algorithm {alg}")
    key = decoded_public_key_to_cryptography(decoded)
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return der, alg


def verify_registration(settings: Settings, credential: dict, *, challenge: bytes) -> RegisteredCredential:
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.rp_id,
            expected_origin=settings.origin,
            require_user_presence=True,
            require_user_verification=True,
            supported_pub_key_algs=SUPPORTED_ALGS,
        )
    except (WebAuthnException, KeyError, TypeError, ValueError) as exc:
        raise WebAuthnError(f"registration failed: {exc}") from exc
    der, alg = cose_to_der(verified.credential_public_key)
    return RegisteredCredential(
        credential_id=verified.credential_id,
        public_key_der=der,
        public_key_cose=verified.credential_public_key,
        alg=alg,
        sign_count=verified.sign_count,
    )


def authentication_options(settings: Settings, *, challenge: bytes, credential_ids: list[bytes]) -> dict:
    opts = generate_authentication_options(
        rp_id=settings.rp_id,
        challenge=challenge,
        timeout=120_000,
        allow_credentials=[PublicKeyCredentialDescriptor(id=c) for c in credential_ids],
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return json.loads(options_to_json(opts))


def verify_assertion(settings: Settings, credential: dict, *, challenge: bytes, public_key_cose: bytes,
                     sign_count: int) -> int:
    """Verify an assertion over `challenge`; returns the new sign count."""
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.rp_id,
            expected_origin=settings.origin,
            credential_public_key=public_key_cose,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )
    except (WebAuthnException, KeyError, TypeError, ValueError) as exc:
        raise WebAuthnError(f"assertion failed: {exc}") from exc
    if not verified.user_verified:
        raise WebAuthnError("assertion failed: user verification is required")
    return verified.new_sign_count
