# crypto_utils.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature
)
from cryptography.hazmat.backends import default_backend
import os

KEY_DIR = "keys"
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public_key.pem")


# -----------------------------------------------------
# GENERATE KEYS
# -----------------------------------------------------
def generate_keys():
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Guardar privada
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Guardar pública
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return PRIVATE_KEY_PATH, PUBLIC_KEY_PATH


# -----------------------------------------------------
# LOAD KEYS
# -----------------------------------------------------
def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )


# -----------------------------------------------------
# HASH DATA
# -----------------------------------------------------
def hash_data(data: str) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    return digest.finalize()


# -----------------------------------------------------
# SIGN DATA
# -----------------------------------------------------
def sign_data(private_key_pem: str, data: bytes) -> str:
    private_key = load_private_key()

    signature = private_key.sign(
        data,
        ec.ECDSA(hashes.SHA256())
    )

    # Firma como hex string
    return signature.hex()

