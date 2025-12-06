# ui.py
import streamlit as st
import requests
from crypto_utils import generate_keys, sign_data, hash_data, derive_shared_key, decrypt_aes_gcm, load_private_key

API_URL = "http://localhost:5000"  # Flask backend

st.title("🚀 Sistema CodeCommit con Criptografía ECDSA + ECDH")


# -----------------------
# GENERAR LLAVES
# -----------------------
if st.button("Generar claves ECDSA"):
    priv, pub = generate_keys()
    st.success(f"Claves generadas:\n- {priv}\n- {pub}")


# -----------------------
# LOGIN
# -----------------------
st.header("🔐 Login")
user_id = st.text_input("ID de Usuario", value="usuario")

if st.button("Login"):
    try:
        r = requests.get(f"{API_URL}/auth/challenge")
        challenge = r.json().get("challenge")
        if not challenge:
            st.error("No se pudo obtener challenge del servidor.")
            st.stop()

        st.write(f"Challenge recibido: `{challenge}`")
        signature_hex = sign_data("keys/private_key.pem", bytes.fromhex(challenge))
        st.write(f"Firma generada: {signature_hex}")

        payload = {"user_id": user_id, "challenge": challenge, "signature": signature_hex}
        r2 = requests.post(f"{API_URL}/auth/verify", json=payload)

        if r2.status_code == 200:
            st.success("🎉 Login exitoso")
        else:
            st.error(f"❌ Autenticación fallida: {r2.json().get('message')}")
    except Exception as e:
        st.error(f"Error: {e}")


# -----------------------
# SUBIR ARCHIVO DE CÓDIGO
# -----------------------
st.header("📤 Subir archivo de código")

uploaded_file = st.file_uploader("Selecciona un archivo de código", type=["py", "txt", "c", "cpp", "java"])
if uploaded_file:
    file_content = uploaded_file.read().decode("utf-8")
    st.code(file_content)
    if st.button("Commit archivo"):
        try:
            h = hash_data(file_content)
            signature_hex = sign_data("keys/private_key.pem", h)
            payload = {"user_id": user_id, "code": file_content, "signature": signature_hex}
            r = requests.post(f"{API_URL}/code/commit", json=payload)
            if r.status_code == 200:
                st.success(f"✅ {r.json().get('message')}")
            else:
                st.error(f"❌ {r.json().get('message')}")
        except Exception as e:
            st.error(f"Error: {e}")


# -----------------------
# DESCARGAR Y DESCIFRAR PARA LÍDER
# -----------------------
st.header("📥 Descargar Código (Líder)")
leader_file = st.text_input("Nombre del archivo cifrado (.enc)", value="repo_usuario_secure.enc")

if st.button("Descifrar archivo"):
    try:
        # 1. Descargar contenido cifrado
        with open(leader_file, "r", encoding="utf-8") as f:
            encrypted_hex = f.read()

        # 2. Cargar clave pública del servidor
        with open("server_keys/server_public.pem", "rb") as f:
            server_pub_bytes = f.read()

        # 3. Derivar la clave AES compartida
        shared_key = derive_shared_key("keys/private_key.pem", server_pub_bytes)

        # 4. Descifrar contenido
        plaintext = decrypt_aes_gcm(shared_key, encrypted_hex)
        st.code(plaintext)
        st.success("Archivo descifrado correctamente")

    except Exception as e:
        st.error(f"Falló descifrado: {e}")
