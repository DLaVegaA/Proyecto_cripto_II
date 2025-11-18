import json
import os

# 1. Leemos la clave pública NUEVA que generó Streamlit
with open("keys/public_key.pem", "rb") as f:
    new_public_key_bytes = f.read()

# Convertimos a string para el JSON
new_public_key_str = new_public_key_bytes.decode('utf-8')

print("Clave nueva leída correctamente.")

# 2. Leemos tu base de datos actual
with open("public_keys.json", "r") as f:
    db = json.load(f)

# 3. Actualizamos al usuario 'anuar' con la clave NUEVA
db["anuar"]["public_key_pem"] = new_public_key_str

# 4. Guardamos el JSON actualizado
with open("public_keys.json", "w") as f:
    json.dump(db, f, indent=4)

print("✅ ¡Listo! public_keys.json actualizado.")
print("⚠️ IMPORTANTE: Reinicia tu servidor Flask (app.py) para que lea los cambios.")