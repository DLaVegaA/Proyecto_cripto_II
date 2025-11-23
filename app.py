import os
import json
from flask import Flask, jsonify, request

# Importa tus funciones de verificación de la Semana 1
from crypto_utils import verify_signature, hash_data

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
        data=challenge_hex  # ¡Importante! Verifica contra los datos originales
    )

    # 4. Devolver el resultado
    if is_valid:
        # ¡Autenticado! [cite: 57]
        return jsonify({"status": "success", "message": f"Usuario {user_id} autenticado."})
    else:
        # ¡Firma inválida!
        return jsonify({"status": "error", "message": "Firma inválida. Autenticación fallida."}), 401


@app.route('/code/commit', methods=['POST'])
def commit_code():
    """
    Recibe el código fuente y su firma.
    Verifica integridad (hash) y autoría (firma).
    """
    data = request.get_json()

    # Validar que lleguen todos los datos
    if not data or 'user_id' not in data or 'code' not in data or 'signature' not in data:
        return jsonify({"status": "error", "message": "Faltan datos (user_id, code, signature)."}), 400

    user_id = data['user_id']
    code_content = data['code']
    signature_hex = data['signature']

    # 1. Obtener clave pública del usuario
    public_key_pem_bytes = get_public_key(user_id)
    if not public_key_pem_bytes:
        return jsonify({"status": "error", "message": "Usuario no encontrado."}), 404

    try:
        # 2. Convertir firma de hex a bytes
        signature_bytes = bytes.fromhex(signature_hex)

        # 3. Calcular el hash del código recibido
        # El cliente firmó el HASH del código, no el código crudo.
        # Para verificar, debemos reconstruir ese hash aquí.
        code_hash_bytes = hash_data(code_content)
        code_hash_hex = code_hash_bytes.hex()

        # 4. Verificar la firma
        # Le pasamos el hash (en hex) a verify_signature, igual que hicimos con el challenge.
        is_valid = verify_signature(
            public_key_pem=public_key_pem_bytes,
            signature=signature_bytes,
            data=code_hash_hex
        )

        if is_valid:
            # 5. Si es válido, guardamos el archivo (Simulación de repositorio)
            filename = f"repo_{user_id}_commit.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(code_content)

            return jsonify({
                "status": "success",
                "message": f"Commit aceptado. Código guardado en {filename}"
            })
        else:
            return jsonify(
                {"status": "error", "message": "Integridad fallida: La firma no coincide con el código."}), 401

    except Exception as e:
        return jsonify({"status": "error", "message": f"Error procesando commit: {str(e)}"}), 500


# Esto permite correr el servidor directamente con: python app.py
if __name__ == '__main__':
    app.run(debug=True, port=5000)