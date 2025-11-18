# main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import os
import secrets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import uvicorn

app = FastAPI()

# ---------------------------
# Cargar clave pública del usuario
# ---------------------------
PUBLIC_KEY_PATH = os.path.join(os.path.dirname(__file__), "../keys/public_key.pem")
PUBLIC_KEY_PATH = os.path.abspath(PUBLIC_KEY_PATH)

print("USANDO PUBLIC KEY PATH:", PUBLIC_KEY_PATH)

with open(PUBLIC_KEY_PATH, "r") as f:
    print("CONTENIDO PUBLIC KEY BACKEND:")
    print(f.read())



if not os.path.exists(PUBLIC_KEY_PATH):
    raise Exception("ERROR: No se encontró la clave pública del usuario.")

with open(PUBLIC_KEY_PATH, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# ---------------------------
# Almacenar challenges
# ---------------------------
current_challenge = None


# ---------------------------
# MODELOS
# ---------------------------
class VerifyRequest(BaseModel):
    signature: str

class CommitRequest(BaseModel):
    code: str
    signature: str


# ---------------------------
# RUTA: Obtener desafío
# ---------------------------
@app.get("/auth/challenge")
def get_challenge():
    global current_challenge
    current_challenge = secrets.token_hex(32)
    return {"challenge": current_challenge}


# ---------------------------
# RUTA: Verificar firma del challenge
# ---------------------------
@app.post("/auth/verify")
def verify_signature(data: VerifyRequest):
    global current_challenge

    if not current_challenge:
        raise HTTPException(400, "No hay challenge generado.")

    try:
        signature_bytes = bytes.fromhex(data.signature)

        # IMPORTANTE: interpretar el challenge como HEX
        challenge_bytes = bytes.fromhex(current_challenge)

        public_key.verify(
            signature_bytes,
            challenge_bytes,
            ec.ECDSA(hashes.SHA256())
        )

        current_challenge = None
        return {"status": "success", "message": "Autenticación exitosa"}

    except Exception as e:
        raise HTTPException(401, f"Firma inválida: {e}")



# ---------------------------
# RUTA: Commit de código
# ---------------------------
@app.post("/code/commit")
def commit_code(data: CommitRequest):
    try:
        signature_bytes = bytes.fromhex(data.signature)

        # Verificar hash del código
        digest = hashes.Hash(hashes.SHA256())
        digest.update(data.code.encode())
        code_hash = digest.finalize()

        public_key.verify(
            signature_bytes,
            code_hash,
            ec.ECDSA(hashes.SHA256())
        )

        # Guardar commit como archivo
        with open("repo_commits.txt", "a") as f:
            f.write("\n--- Nuevo commit ---\n")
            f.write(data.code)
            f.write("\n---------------------\n")

        return {"status": "success", "message": "Commit válido y almacenado"}

    except Exception as e:
        raise HTTPException(401, f"Firma del commit inválida: {e}")


# ---------------------------
# MAIN
# ---------------------------
if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

