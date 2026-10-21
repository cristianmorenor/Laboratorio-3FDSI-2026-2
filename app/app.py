"""NetOps Automation Console - version corregida (Lab 3, FDSI).

Version endurecida de app-vulnerable/. Cada correccion referencia el
hallazgo VULN-n documentado en docs/APP.md.
"""
import ipaddress
import os
import secrets
import sqlite3
import subprocess
from functools import wraps

import yaml
from flask import Flask, abort, jsonify, render_template, request, send_file, session
from werkzeug.utils import safe_join
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
# VULN-1: el secreto viene del entorno; si falta, se genera uno aleatorio por proceso
app.config.update(
    SECRET_KEY=os.environ.get("NETOPS_SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("NETOPS_COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=64 * 1024,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("NETOPS_DB", os.path.join(BASE_DIR, "netops.db"))
LOG_DIR = os.path.join(BASE_DIR, "logs")
ALLOWED_LOGS = {"ping.log"}  # VULN-6: lista blanca de archivos descargables


def db():
    return sqlite3.connect(DB_PATH)


def init_db():
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(os.path.join(LOG_DIR, "ping.log"), "a", encoding="utf-8") as f:
        f.write("netops console iniciada\n")
    con = db()
    con.execute("CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY, name TEXT, ip TEXT, vendor TEXT)")
    con.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    if not con.execute("SELECT 1 FROM devices LIMIT 1").fetchone():
        con.executemany(
            "INSERT INTO devices (name, ip, vendor) VALUES (?, ?, ?)",
            [("sw-core-01", "10.0.0.1", "Cisco"), ("rtr-edge-01", "10.0.0.254", "Juniper"),
             ("sw-access-07", "10.0.7.2", "HP")],
        )
    if not con.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        # VULN-2: hash con sal (scrypt) y contrasena inicial fuera del codigo
        pwd = os.environ.get("NETOPS_ADMIN_PASSWORD")
        if not pwd:
            pwd = secrets.token_urlsafe(12)
            print("[netops] contrasena inicial de admin (solo se muestra una vez): " + pwd, flush=True)
        con.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    ("admin", generate_password_hash(pwd), "admin"))
    con.commit()
    con.close()


def login_required(view):
    # VULN-9: control de acceso en rutas operativas
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user" not in session:
            return jsonify(error="autenticacion requerida"), 401
        return view(*args, **kwargs)
    return wrapped


@app.after_request
def security_headers(resp):
    # VULN-10: cabeceras de seguridad
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/")
def index():
    return render_template("index.html", devices=db().execute("SELECT * FROM devices").fetchall())


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/devices")
def devices():
    q = request.args.get("q", "")
    # VULN-3: consulta parametrizada
    rows = db().execute(
        "SELECT id, name, ip, vendor FROM devices WHERE name LIKE ?", ("%" + q + "%",)
    ).fetchall()
    return jsonify([dict(zip(("id", "name", "ip", "vendor"), r)) for r in rows])


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("username", "")
    # VULN-3b: consulta parametrizada; la comparacion se hace con el hash con sal
    row = db().execute("SELECT username, password, role FROM users WHERE username = ?", (user,)).fetchone()
    if row and check_password_hash(row[1], request.form.get("password", "")):
        session.clear()
        session["user"], session["role"] = row[0], row[2]
        return jsonify(ok=True, user=row[0], role=row[2])
    return jsonify(ok=False), 401


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify(ok=True)


@app.route("/ping")
@login_required
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN-4: solo direcciones IP validas y sin shell (lista de argumentos)
    try:
        ip = str(ipaddress.ip_address(host))
    except ValueError:
        abort(400, "host debe ser una direccion IP valida")
    try:
        out = subprocess.run(["ping", "-c", "1", "-W", "1", ip], capture_output=True, text=True, timeout=5)  # nosec B603 B607
    except (OSError, subprocess.TimeoutExpired):
        abort(502, "no se pudo ejecutar el diagnostico")
    with open(os.path.join(LOG_DIR, "ping.log"), "a", encoding="utf-8") as f:
        f.write("ping %s rc=%s user=%s\n" % (ip, out.returncode, session["user"]))
    return render_template("result.html", title="Resultado de ping", host=ip, output=out.stdout + out.stderr)


@app.route("/search")
def search():
    # VULN-5: autoescape de Jinja2 (sin |safe)
    return render_template("result.html", title="Busqueda", host=request.args.get("q", ""), output="")


@app.route("/logs")
@login_required
def logs():
    name = request.args.get("file", "ping.log")
    # VULN-6: lista blanca + safe_join
    path = safe_join(LOG_DIR, name) if name in ALLOWED_LOGS else None
    if not path or not os.path.isfile(path):
        abort(404)
    return send_file(path, mimetype="text/plain")


@app.route("/import", methods=["POST"])
@login_required
def import_inventory():
    # VULN-7: safe_load, sin instanciar objetos arbitrarios
    try:
        data = yaml.safe_load(request.get_data(as_text=True))
    except yaml.YAMLError:
        abort(400, "YAML invalido")
    return jsonify(received=len(data) if hasattr(data, "__len__") else 1)


if __name__ == "__main__":
    init_db()
    # VULN-8: sin debug y escuchando solo en loopback por defecto
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)
