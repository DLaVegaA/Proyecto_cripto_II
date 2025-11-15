from flask import Flask

# Inicializa la aplicación Flask
app = Flask(__name__)

@app.route('/')
def home():
    """
    Ruta de inicio para verificar que el servidor está funcionando.
    """
    return "¡El servidor API de criptografía está en funcionamiento!"

# Esto permite correr el servidor directamente con: python app.py
if __name__ == '__main__':
    # debug=True reinicia el servidor automáticamente con cada cambio
    app.run(debug=True, port=5000)