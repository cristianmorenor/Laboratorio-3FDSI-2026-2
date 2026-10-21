# NetOps Automation Console — aplicación del Lab 3

Mini servicio Flask (`app/`) que simula una consola para ejecutar
diagnósticos sobre equipos de red. Es **deliberadamente vulnerable**
para que las tres técnicas de análisis tengan material real.
Usar solo en la red del laboratorio.

## Ejecutar

```bash
# Local
cd app && python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt && python app.py      # http://localhost:5000

# Docker
docker build -t netops app && docker run --rm -p 5000:5000 netops

# Pruebas
pip install pytest && pytest tests
```

## Endpoints

| Ruta | Función |
|---|---|
| `GET /` | Inventario de equipos |
| `GET /health` | Estado |
| `GET /devices?q=` | Búsqueda de equipos (JSON) |
| `POST /login` | Autenticación (`admin` / `admin123`) |
| `GET /ping?host=` | Ping a un equipo |
| `GET /search?q=` | Búsqueda con eco del término |
| `GET /logs?file=` | Descarga de logs |
| `POST /import` | Importa inventario YAML |

## Catálogo de vulnerabilidades (para el análisis)

| ID | Vulnerabilidad | CWE | Detecta | Corrección propuesta |
|---|---|---|---|---|
| VULN-1 | `SECRET_KEY` hardcodeada | 798 | SAST (Bandit B105) | Leer de variable de entorno |
| VULN-2 | Contraseñas con MD5 sin sal | 327/916 | SAST (B324) | `argon2`/`bcrypt` |
| VULN-3 | SQL injection en `/devices` y `/login` | 89 | DAST (ZAP), SAST | Consultas parametrizadas |
| VULN-4 | Inyección de comandos en `/ping` | 78 | SAST (B602), DAST | Validar IP + `subprocess` sin shell, lista de argumentos |
| VULN-5 | XSS reflejado en `/search` | 79 | DAST (ZAP) | Quitar `|safe`, autoescape |
| VULN-6 | Path traversal en `/logs` | 22 | DAST | `safe_join` + lista blanca |
| VULN-7 | `yaml.load` inseguro en `/import` | 502 | SAST (B506), SCA | `yaml.safe_load` |
| VULN-8 | `debug=True`, bind `0.0.0.0` | 489/668 | SAST (B201/B104), DAST | Gunicorn, debug off |
| VULN-9 | Sin autenticación en rutas operativas | 306 | DAST | Sesiones + control de acceso (Lab 4) |
| VULN-10 | Sin cabeceras de seguridad / contenedor como root | 693/250 | DAST, Trivy | Cabeceras, `USER` no root |
| SCA | Dependencias antiguas (`PyYAML 5.3.1`, `requests 2.25.0`, `urllib3 1.26.4`, `Flask 2.0.1`, `Werkzeug 2.0.1`, `gunicorn 20.0.4`) | — | pip-audit, Trivy, Dependabot | Actualizar versiones |

## Análisis automatizado

El workflow `.github/workflows/security.yml` ejecuta en cada push:

- **SAST**: Bandit → artefacto `sast-bandit`
- **SCA**: pip-audit sobre `app/requirements.txt` → artefacto `sca-pip-audit`
- **DAST**: construye la imagen, la levanta y corre ZAP baseline → artefacto `dast-zap`

Manual:

```bash
bandit -r app
pip-audit -r app/requirements.txt
zap-baseline.py -t http://$TARGET_IP:5000 -r zap.html
```
