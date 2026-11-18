# backend/app/services/device_sig.py
"""
Device signatures on ballot packages (Algorithm 1, step 4; non-repudiation).
───────────────────────────────────────────────────────────────────────────────

At enrolment the phone generates an ECDSA P-256 key pair inside its secure
hardware (iOS Secure Enclave / Android StrongBox support P-256) and registers
the public key, which is bound to the voter's one-time ticket. Each ballot
package is signed over its canonical bytes:

    SHA-256( election_id | ticket | k | ciphertext | proof | ts )

The server verifies the signature against the key stored with the ticket
before consuming the ticket. Neither the key nor the signature is written to
the ledger, so the stored ballot stays unlinkable to the voter.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def package_bytes(election_id: str, uti: str, num_candidates: int,
                  ciphertext: str, zkp_proof: str, ts: float) -> bytes:
    return "|".join([election_id, uti, str(num_candidates), ciphertext,
                     zkp_proof or "", f"{ts:.3f}"]).encode()


def new_device_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_key_hex(key: ec.EllipticCurvePrivateKey) -> str:
    return key.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint).hex()


def sign(key: ec.EllipticCurvePrivateKey, message: bytes) -> str:
    return key.sign(message, ec.ECDSA(hashes.SHA256())).hex()


def verify(public_key_hex_str: str, signature_hex: str, message: bytes) -> bool:
    try:
        pub = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes.fromhex(public_key_hex_str))
        pub.verify(bytes.fromhex(signature_hex), message, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
