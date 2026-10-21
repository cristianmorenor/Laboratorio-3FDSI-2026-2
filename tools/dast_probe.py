#!/usr/bin/env python3
"""Sondas DAST dirigidas (stdlib) contra la consola NetOps en ejecucion.

Complementa a OWASP ZAP: confirma de forma reproducible cada hallazgo VULN-n.
Uso (autenticado: DAST_USER/DAST_PASS): python3 tools/dast_probe.py http://127.0.0.1:5000 [salida.md]
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def req(base, path, data=None, cookie=None):
    r = urllib.request.Request(base + path, data=data.encode() if isinstance(data, str) else data)
    if cookie:
        r.add_header("Cookie", cookie)
    try:
        resp = urllib.request.urlopen(r, timeout=10)
    except urllib.error.HTTPError as e:
        resp = e
    return resp.status if hasattr(resp, "status") else resp.code, resp.read().decode(errors="replace"), resp.headers


def run(base, cookie=None):
    q = urllib.parse.quote
    out = []

    def get(base, path, data=None):
        return req(base, path, data, cookie)

    def add(vid, name, vulnerable, detail):
        out.append((vid, name, "VULNERABLE" if vulnerable else "protegido", detail))

    s, b, _ = get(base, "/login", "username=" + q("admin' --") + "&password=x")
    add("VULN-3b", "SQLi en /login (bypass de autenticacion)", s == 200 and '"ok":true' in b.replace(" ", ""), "HTTP %s" % s)
    s, b, _ = get(base, "/devices?q=" + q("zzz' OR 1=1 --"))
    add("VULN-3", "SQLi en /devices", s == 200 and len(json.loads(b)) > 0, "filas devueltas: %s" % (len(json.loads(b)) if s == 200 else "-"))
    s, b, _ = get(base, "/ping?host=" + q("127.0.0.1;echo INJ$((40+2))"))
    add("VULN-4", "Inyeccion de comandos en /ping", "INJ42" in b, "HTTP %s" % s)
    s, b, _ = get(base, "/search?q=" + q("<script>alert(1)</script>"))
    add("VULN-5", "XSS reflejado en /search", "<script>alert(1)</script>" in b, "HTTP %s" % s)
    s, b, _ = get(base, "/logs?file=" + q("../app.py"))
    add("VULN-6", "Path traversal en /logs", s == 200 and "Flask" in b, "HTTP %s" % s)
    s, b, _ = get(base, "/import", "!!python/object/apply:builtins.len [[1,2,3]]")
    add("VULN-7", "Deserializacion YAML insegura en /import", s == 200, "HTTP %s" % s)
    s, b, _ = get(base, "/console")
    add("VULN-8", "Consola del depurador Werkzeug expuesta", s == 200 and "Console" in b, "HTTP %s" % s)
    s, b, _ = req(base, "/ping?host=127.0.0.1")  # siempre sin sesion
    add("VULN-9", "Ruta operativa /ping sin autenticacion", s == 200, "HTTP %s" % s)
    s, b, h = get(base, "/")
    missing = [x for x in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy") if x not in h]
    add("VULN-10", "Cabeceras de seguridad ausentes", bool(missing), "faltan: %s" % (", ".join(missing) or "ninguna"))
    return out


def session_cookie(base):
    """Con DAST_USER/DAST_PASS inicia sesion para que las sondas lleguen al codigo protegido."""
    user, pwd = os.environ.get("DAST_USER"), os.environ.get("DAST_PASS")
    if not user:
        return None
    body = urllib.parse.urlencode({"username": user, "password": pwd})
    _, _, h = req(base, "/login", body)
    return (h.get("Set-Cookie") or "").split(";")[0] or None


if __name__ == "__main__":
    rows = run(sys.argv[1].rstrip("/"), session_cookie(sys.argv[1].rstrip("/")))
    text = "| ID | Prueba | Resultado | Detalle |\n|---|---|---|---|\n" + "\n".join("| %s | %s | %s | %s |" % r for r in rows) + "\n"
    print(text)
    if len(sys.argv) > 2:
        open(sys.argv[2], "w", encoding="utf-8").write(text)
    sys.exit(1 if any(r[2] == "VULNERABLE" for r in rows) else 0)
