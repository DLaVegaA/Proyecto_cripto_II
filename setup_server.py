# setup_server.py
from crypto_utils import generate_keys
import os
import shutil

print("Generando llaves del Servidor...")
# Esto sobreescribirá keys/ temporalmente, así que las movemos rápido
priv, pub = generate_keys()

if not os.path.exists("server_keys"):
    os.makedirs("server_keys")

# Movemos las llaves generadas a la carpeta del servidor
shutil.move("keys/private_key.pem", "server_keys/server_private.pem")
shutil.move("keys/public_key.pem", "server_keys/server_public.pem")

print("✅ Llaves del servidor listas en 'server_keys/'.")
print("⚠️ IMPORTANTE: Si borraste tus llaves de usuario 'keys/', regeneralas en la UI.")