import os
import json
from flask import Flask, jsonify, request

# Importa tus funciones de verificación de la Semana 1
from crypto_utils import verify_signature

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
    Genera un desafío aleatorio criptográficamente seguro[cite: 54].
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
    Verifica la firma de un desafío[cite: 56].
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
        data=challenge_hex  # ¡Importante! Verifica contra los datos originales
    )

    # 4. Devolver el resultado
    if is_valid:
        # ¡Autenticado! [cite: 57]
        return jsonify({"status": "success", "message": f"Usuario {user_id} autenticado."})
    else:
        # ¡Firma inválida!
        return jsonify({"status": "error", "message": "Firma inválida. Autenticación fallida."}), 401


# Esto permite correr el servidor directamente con: python app.py
if __name__ == '__main__':
    app.run(debug=True, port=5000)