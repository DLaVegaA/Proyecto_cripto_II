# crypto_utils.py
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


# --- GENERACIÓN DE LLAVES ---
def generate_keys(custom_dir=KEY_DIR):
    """Genera llaves y las guarda en el directorio especificado"""
    if not os.path.exists(custom_dir):
        os.makedirs(custom_dir)

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    priv_path = os.path.join(custom_dir, "private_key.pem")
    pub_path = os.path.join(custom_dir, "public_key.pem")

    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(pub_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    # Devolvemos el contenido de la pública para registrarla
    with open(pub_path, "r") as f:
        pub_pem_str = f.read()

    return priv_path, pub_path, pub_pem_str


# --- UTILIDADES ---
def load_private_key_obj(path=PRIVATE_KEY_PATH):
    with open(path, "rb") as f:
        return load_pem_private_key(f.read(), password=None, backend=default_backend())


def hash_data(data: str) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    return digest.finalize()


# --- FIRMA ---
def sign_data(private_key_path, data: bytes) -> str:
    private_key = load_private_key_obj(private_key_path)
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature.hex()


def verify_signature(public_key_pem: bytes, signature: bytes, data: str) -> bool:
    try:
        public_key = load_pem_public_key(public_key_pem)
        # Manejo flexible de datos (hex o raw)
        try:
            original_data_bytes = bytes.fromhex(data)
        except ValueError:
            original_data_bytes = data.encode()

        public_key.verify(signature, original_data_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError) as e:
        print(f"Error verificación: {e}")
        return False


# --- CIFRADO ---
def derive_shared_key(private_key_path, peer_public_key_bytes):
    """ECDH: Mi Privada + Su Pública = Secreto Compartido"""
    my_private_key = load_pem_private_key(
        open(private_key_path, "rb").read(),
        password=None,
        backend=default_backend()
    )
    peer_public_key = load_pem_public_key(peer_public_key_bytes)

    shared_secret = my_private_key.exchange(ec.ECDH(), peer_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data',
    ).derive(shared_secret)
    return derived_key


def encrypt_data(key: bytes, plaintext: str) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, None)
    return (nonce + ciphertext).hex()


def decrypt_data(key: bytes, ciphertext_hex: str) -> str:
    aesgcm = AESGCM(key)
    full_data = bytes.fromhex(ciphertext_hex)
    nonce = full_data[:12]
    ciphertext = full_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

