# ui.py
import streamlit as st
import requests
from crypto_utils import (
    generate_keys,
    load_private_key,
    hash_data,
    sign_data
)

API_URL = "http://localhost:5000"  # Ajusta tu backend

st.title("🚀 Sistema CodeCommit con Criptografía ECDSA")


# --------------------------------------------------------
# GENERAR CLAVES
# --------------------------------------------------------
if st.button("Generar claves ECDSA"):
    priv, pub = generate_keys()
    st.success(f"Claves generadas:\n- {priv}\n- {pub}")


# --------------------------------------------------------
# LOGIN
# --------------------------------------------------------
st.header("🔐 Login")
user_id = st.text_input("ID de Usuario", value="anuar")

if st.button("Login"):
    try:
        # (1) Obtener challenge
        r = requests.get(f"{API_URL}/auth/challenge")
        challenge = r.json()["challenge"]

        if not challenge:
            st.error("Error conectando con el servidor (No challenge)")
            st.stop()

        st.write(f"Challenge recibido: `{challenge}`")

        # (2) Firmar challenge
        # Convertimos el challenge hex a bytes para firmarlo
        challenge_bytes = bytes.fromhex(challenge)
        signature_hex = sign_data("keys/private_key.pem", challenge_bytes)

        st.write("Firma generada:", signature_hex)

        payload = {
            "user_id": user_id,
            "challenge": challenge,
            "signature": signature_hex
        }

        # (3) Enviar firma al backend
        r = requests.post(
            f"{API_URL}/auth/verify",
            json=payload
        )

        if r.status_code == 200:
            st.success("🎉 Login exitoso")
        else:
            st.error("❌ Error de autenticación")

    except Exception as e:
        st.error(f"Error: {e}")





# --------------------------------------------------------
# SUBIR ARCHIVO DE CÓDIGO
# --------------------------------------------------------
st.header("📤 Subir archivo de código")

uploaded_file = st.file_uploader("Selecciona un archivo de código", type=["py", "txt", "c", "cpp", "java"])

if uploaded_file is not None:
    file_content = uploaded_file.read().decode("utf-8")

    st.write("Contenido del archivo:")
    st.code(file_content)

    if st.button("Commit archivo"):
        try:
            # (1) Hash del contenido
            h = hash_data(file_content)

            # (2) Firma del hash
            signature_hex = sign_data("keys/private_key.pem", h)

            # (3) Enviar al backend
            r = requests.post(
                f"{API_URL}/code/commit",
                json={
                    "code": file_content,
                    "signature": signature_hex
                }
            )

            if r.status_code == 200:
                st.success("Archivo enviado y firmado correctamente.")
            else:
                st.error(f"Error al enviar el archivo: {r.text}")

        except Exception as e:
            st.error(f"Error: {e}")
