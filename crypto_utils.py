import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature


def hash_data(data: str) -> bytes:
    """
    Calcula el hash SHA-256 de una cadena de texto y devuelve los bytes del hash.
    """
    # Convertimos el string a bytes
    data_bytes = data.encode('utf-8')

    # Creamos el objeto hash
    sha256 = hashlib.sha256()

    # Actualizamos el hash con nuestros datos
    sha256.update(data_bytes)

    # Devolvemos el digest (el hash en bytes)
    return sha256.digest()


def verify_signature(public_key_pem: bytes, signature: bytes, data: str) -> bool:
    """
    Verifica una firma ECDSA.

    Parámetros:
    - public_key_pem: La clave pública en formato PEM (como bytes).
    - signature: La firma digital recibida (como bytes).
    - data: Los datos originales (string) que supuestamente fueron firmados.
    """
    try:
        # 1. Cargar la clave pública desde el formato PEM
        public_key = load_pem_public_key(public_key_pem)

        # 2. Recalcular el hash de los datos originales
        #    La firma se hace sobre el hash, no sobre los datos crudos.
        data_hash = hash_data(data)

        # 3. Verificar la firma usando la clave pública
        public_key.verify(
            signature,
            data_hash,  # El hash que acabamos de calcular
            ec.ECDSA(hashes.SHA256())  # Especificamos el algoritmo de firma
        )

        # Si la función .verify() no lanza una excepción, la firma es válida.
        print("Verificación de firma: Exitosa")
        return True

    except InvalidSignature:
        # La firma no coincide.
        print("Verificación de firma: ¡FALLIDA! Firma inválida.")
        return False
    except Exception as e:
        # Otro error (ej. mal formato de clave, etc.)
        print(f"Error al verificar la firma: {e}")
        return False