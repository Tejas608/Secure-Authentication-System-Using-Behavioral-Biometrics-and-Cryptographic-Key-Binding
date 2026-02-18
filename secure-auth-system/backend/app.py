import sys
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import os

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

from backend import auth

app = Flask(__name__)
CORS(app)

@app.route("/health")
def health():
    return {"status": "ok"}

@app.route("/api/register", methods=["POST"])
def register():
    body = request.get_json(force=True)
    username = body.get("username", "").strip()
    password = body.get("password", "")
    password_samples = body.get("passwordSamples", [])
    result = auth.register_user(username, password, password_samples)
    status = 200 if result.get("ok") else 400
    return jsonify(result), status

@app.route("/api/login", methods=["POST"])
def login():
    body = request.get_json(force=True)
    username = body.get("username", "").strip()
    password = body.get("password", "")
    keystrokes = body.get("keystrokes", [])
    result = auth.authenticate_user(username, password, keystrokes)
    status = 200 if result.get("ok") else 401
    return jsonify(result), status

@app.route("/")
def serve_frontend():
    frontend_dir = BASE_DIR / "frontend"
    return send_from_directory(frontend_dir, "login.html")

@app.route("/keystroke.js")
def serve_keystroke_js():
    frontend_dir = BASE_DIR / "frontend"
    return send_from_directory(frontend_dir, "keystroke.js")

@app.route("/dashboard")
def dashboard():
    frontend_dir = BASE_DIR / "frontend"
    return send_from_directory(frontend_dir, "dashboard.html")

@app.route("/frontend/<path:path>")
def static_proxy(path):
    frontend_dir = BASE_DIR / "frontend"
    return send_from_directory(frontend_dir, path)

if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port_str = os.environ.get("PORT", "5000")
    try:
        port = int(port_str)
    except ValueError:
        port = 5000

    debug_env = os.environ.get("FLASK_DEBUG")
    debug = True if debug_env is None else (debug_env.strip() in ("1", "true", "True"))
    app.run(host=host, port=port, debug=debug)