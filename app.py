# app.py
import os
import json
import shutil
from flask import Flask, jsonify, request
from crypto_utils import verify_signature, hash_data, encrypt_data, derive_shared_key, generate_keys

app = Flask(__name__)
DB_FILE = 'public_keys.json'
SERVER_KEYS_DIR = 'server_keys'

# --- AUTO-CONFIGURACIÓN DEL SERVIDOR ---
if not os.path.exists(SERVER_KEYS_DIR):
    print("⚙️ Inicializando llaves del servidor...")
    # Generamos llaves en carpeta temporal y movemos
    generate_keys(SERVER_KEYS_DIR)
    # Renombramos para estandarizar
    os.replace(f"{SERVER_KEYS_DIR}/private_key.pem", f"{SERVER_KEYS_DIR}/server_private.pem")
    os.replace(f"{SERVER_KEYS_DIR}/public_key.pem", f"{SERVER_KEYS_DIR}/server_public.pem")
    print("✅ Llaves del servidor listas.")

if not os.path.exists(DB_FILE):
    print("⚙️ Creando base de datos vacía...")
    with open(DB_FILE, 'w') as f:
        json.dump({}, f)


# --- UTILIDADES ---
def get_public_key(user_id: str) -> bytes | None:
    try:
        with open(DB_FILE, 'r') as f:
            db = json.load(f)
        user = db.get(user_id)
        return user['public_key_pem'].encode('utf-8') if user else None
    except:
        return None


# --- ENDPOINTS ---

@app.route('/')
def home():
    return "Sistema Cripto Activo y Seguro"


@app.route('/register', methods=['POST'])
def register_user():
    """Registra un nuevo usuario (Programador, Líder, Senior) en la BD"""
    data = request.get_json()
    user_id = data.get('user_id')
    role = data.get('role')
    pem = data.get('public_key_pem')

    if not all([user_id, role, pem]):
        return jsonify({"status": "error", "message": "Faltan datos"}), 400

    # Guardar en JSON
    with open(DB_FILE, 'r+') as f:
        try:
            db = json.load(f)
        except json.JSONDecodeError:
            db = {}

        db[user_id] = {"role": role, "public_key_pem": pem}
        f.seek(0)
        json.dump(db, f, indent=4)
        f.truncate()

    return jsonify({"status": "success", "message": f"Usuario {user_id} ({role}) registrado."})


@app.route('/auth/challenge', methods=['GET'])
def get_challenge():
    return jsonify({"challenge": os.urandom(32).hex()})


@app.route('/auth/verify', methods=['POST'])
def verify_auth():
    data = request.get_json()
    user_id = data.get('user_id')
    sig = data.get('signature')
    chal = data.get('challenge')

    pub = get_public_key(user_id)
    if not pub: return jsonify({"status": "error", "message": "Usuario no registrado"}), 404

    if verify_signature(pub, bytes.fromhex(sig), chal):
        return jsonify({"status": "success", "message": "Autenticado"})
    return jsonify({"status": "error", "message": "Firma inválida"}), 401


@app.route('/code/commit', methods=['POST'])
def commit_code():
    data = request.get_json()
    user_id = data.get('user_id')
    code = data.get('code')
    sig = data.get('signature')

    # 1. Verificar usuario
    user_pub = get_public_key(user_id)
    if not user_pub: return jsonify({"error": "Usuario desconocido"}), 404

    # 2. Verificar firma (Integridad)
    if verify_signature(user_pub, bytes.fromhex(sig), hash_data(code).hex()):

        # 3. Cifrar para el LÍDER (Confidencialidad)
        leader_pub = get_public_key("lider")  # Asumiremos que el rol líder tiene ID 'lider'
        if not leader_pub:
            # Fallback: Si no hay lider registrado, buscamos por rol en el JSON
            with open(DB_FILE) as f:
                db = json.load(f)
                for uid, info in db.items():
                    if info['role'].lower() == 'lider':
                        leader_pub = info['public_key_pem'].encode()
                        break

        if not leader_pub:
            return jsonify({"status": "error", "message": "No existe un Líder registrado para cifrar el código."}), 500

        # ECDH + AES
        shared_key = derive_shared_key(f"{SERVER_KEYS_DIR}/server_private.pem", leader_pub)
        enc_hex = encrypt_data(shared_key, code)

        filename = f"repo_{user_id}_secure.enc"
        with open(filename, "w", encoding="utf-8") as f:
            f.write(enc_hex)

        return jsonify({"status": "success", "message": f"Código cifrado y guardado: {filename}"})

    return jsonify({"status": "error", "message": "Integridad fallida"}), 401


if __name__ == '__main__':
    app.run(debug=True, port=5000)