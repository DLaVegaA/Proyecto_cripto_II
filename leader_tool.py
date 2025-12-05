# leader_tool.py
import os
import json
from crypto_utils import generate_keys, derive_shared_key, decrypt_data, load_pem_public_key

# Rutas de archivos
LEADER_KEYS_DIR = "leader_keys"
LEADER_PRIV = os.path.join(LEADER_KEYS_DIR, "leader_private.pem")
LEADER_PUB = os.path.join(LEADER_KEYS_DIR, "leader_public.pem")

SERVER_PUB_KEY_PATH = "server_keys/server_public.pem"  # Necesitamos la pública del servidor


def setup_leader():
    """Genera las llaves del Líder si no existen"""
    if not os.path.exists(LEADER_KEYS_DIR):
        print("🔵 Generando identidad del Líder...")
        os.makedirs(LEADER_KEYS_DIR)
        # Usamos la función de utils, pero movemos los archivos a nuestra carpeta
        temp_priv, temp_pub = generate_keys()
        os.replace(temp_priv, LEADER_PRIV)
        os.replace(temp_pub, LEADER_PUB)

        # MOSTRAR LA LLAVE PÚBLICA PARA REGISTRARLA EN EL SERVIDOR
        with open(LEADER_PUB, "r") as f:
            print(f"\n✅ Llaves creadas. COPIA ESTA LLAVE PÚBLICA EN 'public_keys.json' bajo 'leader_project':\n")
            print(f.read())
    else:
        print("✅ Identidad del Líder encontrada.")


def decrypt_file(filename):
    """Proceso de descifrado"""
    if not os.path.exists(filename):
        print(f"❌ El archivo {filename} no existe.")
        return

    # 1. Cargar contenido cifrado
    with open(filename, "r", encoding="utf-8") as f:
        encrypted_content = f.read()

    # 2. Cargar Clave Pública del Servidor (El remitente)
    if not os.path.exists(SERVER_PUB_KEY_PATH):
        print("❌ No encuentro la clave pública del servidor. Ejecuta setup_server.py primero.")
        return

    with open(SERVER_PUB_KEY_PATH, "rb") as f:
        server_pub_bytes = f.read()

    # 3. Derivar la llave maestra (ECDH)
    # Misma matemática: Privada Líder + Pública Servidor = Mismo Secreto
    try:
        shared_key = derive_shared_key(LEADER_PRIV, server_pub_bytes)

        # 4. Descifrar
        plaintext = decrypt_data(shared_key, encrypted_content)

        print("\n🔓 --- CONTENIDO DESCIFRADO --- 🔓")
        print(plaintext)
        print("----------------------------------\n")

        # Opcional: Guardar descifrado
        out_file = filename.replace(".enc", "_decrypted.txt")
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(plaintext)
        print(f"✅ Guardado en: {out_file}")

    except Exception as e:
        print(f"❌ Falló el descifrado: {e}")


# --- MENU ---
if __name__ == "__main__":
    setup_leader()
    print("-" * 30)
    file_to_decrypt = input("📂 Ingresa el nombre del archivo cifrado (ej. repo_anuar_secure.enc): ")
    decrypt_file(file_to_decrypt)