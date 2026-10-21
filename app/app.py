"""NetOps Automation Console - mini servicio del Laboratorio 3 (FDSI).

Ejecucion controlada de comandos de diagnostico sobre equipos de red.
IMPORTANTE: contiene vulnerabilidades DELIBERADAS (marcadas con "VULN-n")
para que SAST (Bandit/Semgrep), SCA (pip-audit/Trivy) y DAST (OWASP ZAP)
tengan hallazgos reales. No desplegar fuera de la red del laboratorio.
Ver docs/APP.md para el catalogo y las correcciones propuestas.
"""
import hashlib
import os
import sqlite3
import subprocess

import yaml
from flask import Flask, jsonify, render_template, request, send_file

app = Flask(__name__)
app.config["SECRET_KEY"] = "netops-secret-123"  # VULN-1: secreto hardcodeado (CWE-798)

DB_PATH = os.environ.get("NETOPS_DB", os.path.join(os.path.dirname(__file__), "netops.db"))
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")


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
        # VULN-2: contrasenas con MD5 sin sal (CWE-327 / CWE-916)
        con.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    ("admin", hashlib.md5(b"admin123").hexdigest(), "admin"))
    con.commit()
    con.close()


@app.route("/")
def index():
    return render_template("index.html", devices=db().execute("SELECT * FROM devices").fetchall())


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/devices")
def devices():
    q = request.args.get("q", "")
    # VULN-3: SQL injection por concatenacion (CWE-89)
    rows = db().execute("SELECT id, name, ip, vendor FROM devices WHERE name LIKE '%" + q + "%'").fetchall()
    return jsonify([dict(zip(("id", "name", "ip", "vendor"), r)) for r in rows])


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("username", "")
    pwd = hashlib.md5(request.form.get("password", "").encode()).hexdigest()
    # VULN-3b: SQL injection en autenticacion (CWE-89)
    row = db().execute(
        "SELECT username, role FROM users WHERE username = '%s' AND password = '%s'" % (user, pwd)
    ).fetchone()
    if row:
        return jsonify(ok=True, user=row[0], role=row[1])
    return jsonify(ok=False), 401


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # VULN-4: inyeccion de comandos con shell=True (CWE-78)
    out = subprocess.run("ping -c 1 -W 1 " + host, shell=True, capture_output=True, text=True)
    with open(os.path.join(LOG_DIR, "ping.log"), "a", encoding="utf-8") as f:
        f.write("ping %s rc=%s\n" % (host, out.returncode))
    return render_template("result.html", title="Resultado de ping", host=host, output=out.stdout + out.stderr)


@app.route("/search")
def search():
    # VULN-5: XSS reflejado, la plantilla usa |safe (CWE-79)
    return render_template("result.html", title="Busqueda", host=request.args.get("q", ""), output="", unsafe=True)


@app.route("/logs")
def logs():
    name = request.args.get("file", "ping.log")
    # VULN-6: path traversal (CWE-22)
    return send_file(os.path.join(LOG_DIR, name), mimetype="text/plain")


@app.route("/import", methods=["POST"])
def import_inventory():
    # VULN-7: deserializacion insegura con yaml.load + Loader completo (CWE-502)
    data = yaml.load(request.get_data(as_text=True), Loader=yaml.Loader)
    return jsonify(received=len(data) if hasattr(data, "__len__") else 1)


if __name__ == "__main__":
    init_db()
    # VULN-8: debug=True y bind a todas las interfaces (CWE-489 / CWE-668)
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
