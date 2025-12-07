# crypto_utils.py
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

KEY_DIR = "keys"
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public_key.pem")

# -----------------------
# GENERAR LLAVES
# -----------------------
def generate_keys():
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Guardar privada
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    # Guardar pública
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    return PRIVATE_KEY_PATH, PUBLIC_KEY_PATH


# -----------------------
# CARGAR LLAVES
# -----------------------
def load_private_key(path=PRIVATE_KEY_PATH):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_public_key(path=PUBLIC_KEY_PATH):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


# -----------------------
# HASH
# -----------------------
def hash_data(data: str) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data.encode())
    return digest.finalize()


# -----------------------
# FIRMA & VERIFICACIÓN
# -----------------------
def sign_data(private_key_path, data: bytes) -> str:
    private_key = load_private_key(private_key_path)
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


# -----------------------
# CIFRADO / DESCIFRADO ECDH + AES-GCM
# -----------------------
def derive_shared_key(private_key_path: str, peer_public_key_bytes: bytes) -> bytes:
    """Deriva una clave AES de 32 bytes usando ECDH + HKDF."""
    private_key = load_private_key(private_key_path)
    peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())

    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)
    return derived_key


def decrypt_aes_gcm(key: bytes, ciphertext_hex: str) -> str:
    """Descifra un texto cifrado en AES-GCM (hex: nonce + ciphertext)."""
    aesgcm = AESGCM(key)
    full_bytes = bytes.fromhex(ciphertext_hex)
    nonce, ciphertext = full_bytes[:12], full_bytes[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
