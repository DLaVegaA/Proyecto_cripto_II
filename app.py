import os
import json
from flask import Flask, jsonify, request
from crypto_utils import verify_signature, hash_data, encrypt_data, derive_shared_key

# Inicializa la aplicación Flask
app = Flask(__name__)

# --- Constante ---
DB_FILE = 'public_keys.json'


# --- Funciones Auxiliares ---

def get_public_key(user_id: str) -> bytes | None:
    """
    Carga la clave pública de un usuario desde la "base de datos" JSON.
    """
    try:
        with open(DB_FILE, 'r') as f:
            db = json.load(f)

        user_data = db.get(user_id)
        if user_data:
            # Devuelve la clave como bytes, como espera verify_signature
            return user_data['public_key_pem'].encode('utf-8')

        return None  # Usuario no encontrado
    except FileNotFoundError:
        print(f"ERROR: No se encontró el archivo {DB_FILE}")
        return None
    except Exception as e:
        print(f"Error cargando clave pública: {e}")
        return None


# --- Rutas de API (Semana 1) ---

@app.route('/')
def home():
    """
    Ruta de inicio para verificar que el servidor está funcionando.
    """
    return "¡El servidor API de criptografía está en funcionamiento!"


# --- Rutas de API (Semana 2: Flujo 1 - Autenticación) ---

@app.route('/auth/challenge', methods=['GET'])
def get_challenge():
    """
    Genera un desafío aleatorio criptográficamente seguro.
    Devuelve este desafío al cliente (Streamlit) para que lo firme.
    """
    # Genera 32 bytes aleatorios seguros
    challenge_bytes = os.urandom(32)

    # Convierte los bytes a una cadena hexadecimal para enviarla por JSON
    challenge_hex = challenge_bytes.hex()

    return jsonify({"challenge": challenge_hex})


@app.route('/auth/verify', methods=['POST'])
def verify_authentication():
    """
    Verifica la firma de un desafío.
    Recibe el ID del usuario, el desafío original y la firma.
    """
    data = request.get_json()
    if not data or 'user_id' not in data or 'signature' not in data or 'challenge' not in data:
        return jsonify({"status": "error", "message": "Datos incompletos."}), 400

    user_id = data['user_id']
    challenge_hex = data['challenge']
    signature_hex = data['signature']

    # 1. Obtener la clave pública del usuario desde nuestra "DB"
    public_key_pem_bytes = get_public_key(user_id)
    if not public_key_pem_bytes:
        return jsonify({"status": "error", "message": "Usuario no encontrado."}), 404

    # 2. Convertir la firma (hex) de vuelta a bytes
    try:
        signature_bytes = bytes.fromhex(signature_hex)
    except ValueError:
        return jsonify({"status": "error", "message": "Formato de firma inválido."}), 400

    # 3. Usar tu función de la Semana 1 para verificar la firma
    #    Usamos el 'challenge_hex' como los datos que se firmaron,
    #    ya que eso fue lo que le enviamos al cliente.
    is_valid = verify_signature(
        public_key_pem=public_key_pem_bytes,
        signature=signature_bytes,
        data=challenge_hex
    )

    # 4. Devolver el resultado
    if is_valid:
        # ¡Autenticado!
        return jsonify({"status": "success", "message": f"Usuario {user_id} autenticado."})
    else:
        # ¡Firma inválida!
        return jsonify({"status": "error", "message": "Firma inválida. Autenticación fallida."}), 401


@app.route('/code/commit', methods=['POST'])
def commit_code():
    data = request.get_json()
    if not data or 'user_id' not in data or 'code' not in data or 'signature' not in data:
        return jsonify({"status": "error", "message": "Faltan datos."}), 400

    user_id = data['user_id']
    code_content = data['code']
    signature_hex = data['signature']

    # 1. Verificar firma del USUARIO
    user_pub_key = get_public_key(user_id)
    if not user_pub_key:
        return jsonify({"status": "error", "message": "Usuario no encontrado."}), 404

    try:
        signature_bytes = bytes.fromhex(signature_hex)
        code_hash_hex = hash_data(code_content).hex()

        if verify_signature(user_pub_key, signature_bytes, code_hash_hex):

            # === SEMANA 4: CIFRADO ===
            # Ciframos para el LIDER (leader_project)
            leader_pub_key = get_public_key("leader_project")
            if not leader_pub_key:
                return jsonify({"status": "error", "message": "Falta clave pública del Líder."}), 500

            # ECDH: Llave Privada Servidor + Llave Pública Líder
            server_priv_path = "server_keys/server_private.pem"
            shared_key = derive_shared_key(server_priv_path, leader_pub_key)

            # Cifrar con AES
            encrypted_hex = encrypt_data(shared_key, code_content)

            # Guardar archivo .enc (ilebible)
            filename = f"repo_{user_id}_secure.enc"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(encrypted_hex)

            return jsonify({
                "status": "success",
                "message": f"Código cifrado y guardado en {filename}"
            })
        else:
            return jsonify({"status": "error", "message": "Integridad fallida."}), 401

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# Esto permite correr el servidor directamente con: python app.py
if __name__ == '__main__':
    app.run(debug=True, port=5000)