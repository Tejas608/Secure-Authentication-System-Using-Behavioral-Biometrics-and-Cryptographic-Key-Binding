import base64
import hashlib
from typing import List, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def generate_rsa_keypair() -> Tuple[str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem.decode(), public_pem.decode()

def _features_to_bytes(features: List[float]) -> bytes:
    joined = ",".join(f"{x:.6f}" for x in features)
    return joined.encode()

def derive_binding_key(features: List[float]) -> bytes:
    seed = _features_to_bytes(features)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"keystroke-binding")
    return hkdf.derive(seed)

def bind_public_key(public_key_pem: str, features: List[float]) -> str:
    key = derive_binding_key(features)
    digest = hashlib.sha256(key + public_key_pem.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode()

def verify_binding(public_key_pem: str, features: List[float], binding_token: str) -> bool:
    try:
        expected = bind_public_key(public_key_pem, features)
        return hashlib.compare_digest(expected, binding_token)
    except Exception:
        return False