# crypto_utils.py CORREGIDO
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key
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

    # Usamos SECP256R1 para todo (estándar y seguro)
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    return PRIVATE_KEY_PATH, PUBLIC_KEY_PATH

# -----------------------------------------------------
# LOAD & SIGN
# -----------------------------------------------------
def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def hash_data(data: str) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data.encode())
    return digest.finalize()

def sign_data(private_key_path: str, data: bytes) -> str:
    # Nota: private_key_path es ignorado aquí porque cargamos del path fijo,
    # pero lo dejamos para compatibilidad con tu UI actual.
    private_key = load_private_key()
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature.hex()

# -----------------------------------------------------
# VERIFY (AQUÍ ESTABA EL ERROR)
# -----------------------------------------------------
def verify_signature(public_key_pem: bytes, signature: bytes, data: str) -> bool:
    try:
        public_key = load_pem_public_key(public_key_pem)

        # CORRECCIÓN CRÍTICA:
        # La UI firmó los BYTES derivados del hex. El backend recibe el HEX string.
        # Debemos convertir el hex string de vuelta a bytes para verificar lo mismo.
        try:
            original_data_bytes = bytes.fromhex(data)
        except ValueError:
            # Por si acaso llega texto normal y no hex
            original_data_bytes = data.encode()

        # La librería 'cryptography' hace el hash automáticamente con ec.ECDSA(hashes.SHA256())
        # Tu versión anterior hacía un hash manual ANTES, causando un doble hash.
        public_key.verify(
            signature,
            original_data_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        print("Firma inválida (Criptográficamente no coincide)")
        return False
    except Exception as e:
        print(f"Error en verify: {e}")
        return False