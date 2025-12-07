# crypto_utils.py (Versión Semana 4)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
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
def load_private_key_obj(path=PRIVATE_KEY_PATH):
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=None, backend=default_backend())

# -----------------------
# HASH
# -----------------------
def hash_data(data: str) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    return digest.finalize()

# -----------------------
# FIRMA & VERIFICACIÓN
# -----------------------
def sign_data(private_key_path, data: bytes) -> str:
    private_key = load_private_key_obj()
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature.hex()

def verify_signature(public_key_pem: bytes, signature: bytes, data: str) -> bool:
    try:
        public_key = load_pem_public_key(public_key_pem)
        try:
            original_data_bytes = bytes.fromhex(data)
        except ValueError:
            original_data_bytes = data.encode()

        public_key.verify(signature, original_data_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"Error verify: {e}")
        return False

# -----------------------
# CIFRADO / DESCIFRADO ECDH + AES-GCM
# -----------------------
def derive_shared_key(private_key_pem_path, peer_public_key_bytes):
    """Deriva clave AES compartida usando ECDH."""
    my_private_key = load_pem_private_key(
        open(private_key_pem_path, "rb").read(),
        password=None,
        backend=default_backend()
    )
    peer_public_key = load_pem_public_key(peer_public_key_bytes)

    shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_secret)
    return derived_key

def encrypt_data(key: bytes, plaintext: str) -> str:
    """Cifra texto con AES-GCM. Devuelve Hex (Nonce + Ciphertext)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return (nonce + ciphertext).hex()


def decrypt_data(key: bytes, ciphertext_hex: str) -> str:
    """
    Descifra datos Hex (Nonce + Ciphertext) usando AES-GCM.
    Revierte lo que hizo encrypt_data.
    """
    try:
        aesgcm = AESGCM(key)
        full_data = bytes.fromhex(ciphertext_hex)

        # Extraemos el Nonce (primeros 12 bytes) y el Ciphertext (el resto)
        nonce = full_data[:12]
        ciphertext = full_data[12:]

        # Desciframos
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode('utf-8')
    except Exception as e:
        return f"ERROR DE DESCIFRADO: {str(e)}"

