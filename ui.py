# ui.py
import streamlit as st
import requests
import os
from crypto_utils import generate_keys, sign_data, hash_data, derive_shared_key, decrypt_data

API_URL = "http://localhost:5000"

st.set_page_config(page_title="Sistema Cripto Seguro", layout="wide")
st.title("🛡️ Sistema de Gestión de Código Seguro")

# Menú lateral
menu = st.sidebar.selectbox("Menú", ["Registro de Usuario", "Login & Trabajo", "Herramienta Líder (Descifrar)"])

# ----------------------------------------------------
# 1. REGISTRO (Genera llaves y las manda al server)
# ----------------------------------------------------
if menu == "Registro de Usuario":
    st.header("📝 Registro de Nuevo Usuario")
    new_user = st.text_input("Nombre de Usuario (ID)")
    role = st.selectbox("Rol", ["Programador", "Programador Senior", "Lider"])

    if st.button("Generar Identidad y Registrar"):
        if not new_user:
            st.error("Escribe un nombre de usuario.")
        else:
            # Generamos llaves LOCALMENTE para este usuario
            # Usamos carpetas separadas para simular usuarios distintos en la misma PC
            user_dir = f"keys_{new_user}"
            priv_path, pub_path, pub_pem = generate_keys(user_dir)

            # Enviamos la pública al servidor
            try:
                payload = {"user_id": new_user, "role": role, "public_key_pem": pub_pem}
                r = requests.post(f"{API_URL}/register", json=payload)

                if r.status_code == 200:
                    st.success(f"✅ {r.json()['message']}")
                    st.info(f"Tus llaves se guardaron en la carpeta: {user_dir}/")
                    st.warning("⚠️ GUARDA TU LLAVE PRIVADA, EL SERVIDOR NO LA TIENE.")
                else:
                    st.error("Error en registro.")
            except Exception as e:
                st.error(f"Error conectando al servidor: {e}")

# ----------------------------------------------------
# 2. LOGIN & COMMIT (Flujo diario)
# ----------------------------------------------------
elif menu == "Login & Trabajo":
    st.header("🔐 Autenticación y Envío")

    # Simulamos login cargando la llave de la carpeta del usuario
    login_user = st.text_input("Tu ID de Usuario")
    user_keys_dir = f"keys_{login_user}"

    if os.path.exists(user_keys_dir):
        st.success(f"Llaves encontradas en {user_keys_dir}")

        if st.button("Iniciar Sesión (Firmar Challenge)"):
            try:
                # 1. Pedir Challenge
                r = requests.get(f"{API_URL}/auth/challenge")
                chal = r.json()['challenge']
                st.write(f"Desafío recibido: `{chal}`")

                # 2. Firmar con mi privada
                priv_path = os.path.join(user_keys_dir, "private_key.pem")
                sig = sign_data(priv_path, bytes.fromhex(chal))

                # 3. Verificar
                r2 = requests.post(f"{API_URL}/auth/verify", json={
                    "user_id": login_user, "challenge": chal, "signature": sig
                })

                if r2.status_code == 200:
                    st.success("✅ AUTENTICADO CORRECTAMENTE")
                    st.session_state['authenticated'] = True
                    st.session_state['user'] = login_user
                else:
                    st.error(f"Falló: {r2.json().get('message')}")
            except Exception as e:
                st.error(f"Error: {e}")

        # Si está autenticado, mostrar subida de código
        if st.session_state.get('authenticated') and st.session_state.get('user') == login_user:
            st.divider()
            st.subheader("📤 Subir Código Fuente")
            code_file = st.file_uploader("Archivo (.py, .txt, .c)")

            if code_file and st.button("Firmar y Subir"):
                content = code_file.read().decode('utf-8')
                st.code(content)

                # Hash y Firma
                priv_path = os.path.join(user_keys_dir, "private_key.pem")
                h_content = hash_data(content)
                sig_code = sign_data(priv_path, h_content)

                # Enviar
                r3 = requests.post(f"{API_URL}/code/commit", json={
                    "user_id": login_user, "code": content, "signature": sig_code
                })

                if r3.status_code != 200:
                    st.error(f"Error del Servidor ({r3.status_code}):")
                    st.text(r3.text)  # <-- ESTO TE MOSTRARÁ EL ERROR REAL EN PANTALLA
                else:
                    st.success(f"✅ {r3.json()['message']}")

    else:
        if login_user:
            st.warning("No encuentro tus llaves. ¿Ya te registraste?")

# ----------------------------------------------------
# 3. HERRAMIENTA LÍDER (Descifrado)
# ----------------------------------------------------
elif menu == "Herramienta Líder (Descifrar)":
    st.header("🔓 Panel del Líder")
    st.info("Esta herramienta usa la llave privada del Líder para abrir archivos cifrados por el servidor.")

    leader_id = st.text_input("ID del Líder", value="lider")
    leader_dir = f"keys_{leader_id}"

    if not os.path.exists(leader_dir):
        st.error(f"No encuentro las llaves del líder en {leader_dir}. Regístrate como 'lider' primero.")
    else:
        file_name = st.text_input("Nombre del archivo cifrado", "repo_anuar_secure.enc")

        if st.button("Descifrar"):
            try:
                # Leer encriptado
                with open(file_name, "r", encoding="utf-8") as f:
                    enc_data = f.read()

                # Leer pública del servidor (Remitente)
                with open("server_keys/server_public.pem", "rb") as f:
                    server_pub = f.read()

                # Leer privada del líder (Receptor)
                priv_path = os.path.join(leader_dir, "private_key.pem")

                # Magia ECDH
                shared = derive_shared_key(priv_path, server_pub)
                plain = decrypt_data(shared, enc_data)

                st.success("✅ Archivo Descifrado:")
                st.code(plain)
            except Exception as e:
                st.error(f"Error: {e}")
