"""Standard Ed25519 cryptographic key management and signing utilities.

Never invent custom cryptography: uses standard Ed25519 from cryptography library.
Ed25519 provides fast, deterministic signatures with collision resistance and no random
nonce failure modes.
"""

import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature


def load_or_create_keypair(
    keys_dir: Path | str,
) -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Load existing Ed25519 keypair or generate and persist a new one.

    PROTOTYPE LIMITATION: For this prototype, private keys are stored on local disk
    in PEM format without passphrase encryption. Production systems must store issuer
    private keys in a Hardware Security Module (HSM) or cloud KMS (e.g. AWS KMS, GCP KMS).
    """
    keys_path = Path(keys_dir)
    # Ensure keys directory exists with private permissions
    keys_path.mkdir(parents=True, exist_ok=True)

    priv_file = keys_path / "issuer_private.pem"
    pub_file = keys_path / "issuer_public.pem"

    if priv_file.exists() and pub_file.exists():
        # Security: Load existing private key without password (plaintext PEM in prototype)
        priv_bytes = priv_file.read_bytes()
        private_key = serialization.load_pem_private_key(priv_bytes, password=None)
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise TypeError("Loaded private key is not an Ed25519 key")

        # Security: Load corresponding public key used for token verification
        pub_bytes = pub_file.read_bytes()
        public_key = serialization.load_pem_public_key(pub_bytes)
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise TypeError("Loaded public key is not an Ed25519 key")

        return private_key, public_key

    # Security: Generate standard Ed25519 keypair using OS cryptographically secure entropy
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Security: Export private key in PKCS#8 PEM format
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Security: Export public key in SubjectPublicKeyInfo format for store verification
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Write private key and restrict file permissions where OS supports POSIX modes
    priv_file.write_bytes(priv_pem)
    try:
        # Security: Restrict private key read/write permissions to current user only (0600)
        os.chmod(priv_file, 0o600)
    except (OSError, NotImplementedError):
        # PROTOTYPE LIMITATION: Windows ACLs require win32 security APIs; chmod has limited effect on NTFS
        pass

    # Write public key (safe for distribution to verifiers)
    pub_file.write_bytes(pub_pem)

    return private_key, public_key


def sign(private_key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign arbitrary bytes using the issuer Ed25519 private key.

    Ed25519 signs deterministic hashes of data, producing exactly 64 bytes of signature.
    """
    # Security: Never log data or private key during signing to prevent token leaks
    return private_key.sign(data)


def verify(public_key: ed25519.Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    """Verify an Ed25519 signature over exact data bytes using the public key.

    Security Rule: Return False on ANY failure; NEVER raise exceptions to callers.
    """
    # Security: Reject signatures that are not exactly 64 bytes to prevent parsing edge cases
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != 64:
        return False

    try:
        # Security: Standard Ed25519 verification verifies signature matches exact data bytes
        public_key.verify(signature, data)
        return True
    except (InvalidSignature, Exception):
        # Security: Fail-safe default — any exception or mismatch yields False
        return False


def public_key_to_pem(public_key: ed25519.Ed25519PublicKey) -> str:
    """Export public key as a PEM-encoded SubjectPublicKeyInfo string.

    This PEM string can be shared with stores/verifiers to authenticate tokens.
    """
    pem_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem_bytes.decode("utf-8")
