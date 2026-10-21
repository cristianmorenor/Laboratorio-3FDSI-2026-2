# Seguridad del proyecto — evidencia del laboratorio

## 1. Alcance autorizado
- Repositorio: https://github.com/cristianmorenor/Laboratorio-3FDSI-2026-2
- Tecnología: Python 3 / Flask, SQLite, Docker. Activo principal: consola web que ejecuta diagnósticos (ping) sobre equipos de red; riesgo principal: ejecución remota de comandos sin autenticación.
- Rama base y commit: `main` @ `c25f597` (tag `baseline-lab5`). Rama del laboratorio: `security/lab-fsi`.
- Flujos de autenticación: `POST /login` (línea base: sin sesión ni control de acceso). APIs: `/devices`, `/ping`, `/logs`, `/import`.
- URL de staging propio: no se usó staging HTTPS; alternativa documentada: ZAP baseline contra `localhost` en el runner (`.github/workflows/dast-local.yml`).
- Responsables: Cristian Santiago Moreno Ruiz (Red Team) y David Contreras (Blue Team) — proyecto propio del equipo G01, datos y usuarios ficticios.
- Fuera de alcance: producción, sistemas de terceros, datos reales y pruebas destructivas.

## 2. Línea base y herramientas
| Herramienta | Tipo | Resultado en línea base | Estado | Evidencia |
|---|---|---|---|---|
| Semgrep (`p/owasp-top-ten`, `p/secrets`) | SAST | Pendiente: corre en Actions (el entorno de desarrollo no alcanza `semgrep.dev`) | Workflow listo | artefacto `resultado-semgrep` |
| CodeQL (Default setup) | SAST | Se activa en Settings → Security | Pendiente de activar | pestaña Security |
| Bandit (complemento local) | SAST | 4 altas, 4 medias, 2 bajas | Ejecutado | `evidence/lab5/antes/bandit.txt` |
| Gitleaks v8.18.4 | Secretos | 0 hallazgos en 21 commits | Ejecutado | `evidence/lab5/antes/gitleaks.log` |
| pip-audit + Dependabot | SCA | 72 avisos en 8 paquetes | pip-audit ejecutado; Dependabot configurado (`.github/dependabot.yml`) | `evidence/lab5/antes/pip-audit.txt` |
| OWASP ZAP baseline | DAST pasivo | Pendiente: corre en Actions (`dast-local.yml`; sin Docker en el entorno de desarrollo) | Workflow listo | artefacto `informe-zap-local` |
| Sondas dirigidas (`tools/dast_probe.py`) | Validación manual | 9 de 9 vulnerables | Ejecutado | `evidence/lab5/antes/validacion-manual.md` |

Nota: Gitleaks **no detectó** la `SECRET_KEY` hardcodeada (valor de baja entropía, sin patrón de proveedor); lo encontró Bandit (B105). Una herramienta sola no basta.

## 3. Hallazgos y gestión
| ID | Categoría (OWASP / CWE) | Descripción sin secretos | Riesgo | Archivo/ruta | Cambio | Estado |
|---|---|---|---|---|---|---|
| F-01 | A03 Injection / CWE-78 | `/ping` concatena `host` en un comando con `shell=True` | **Crítico** (C/I/D) | `app/app.py` `/ping` | Validar IP con `ipaddress`, `subprocess` sin shell y con timeout | Corregido |
| F-02 | A03 Injection / CWE-89 | SQL por concatenación en `/devices` y `/login` (bypass de login) | **Crítico** | `app/app.py` | Consultas parametrizadas | Corregido |
| F-03 | A08 Integridad / CWE-502 | `yaml.load` con `Loader` completo en `/import` | **Crítico** | `app/app.py` | `yaml.safe_load` | Corregido |
| F-04 | A05 Misconfig / CWE-489, 668 | `debug=True` (consola Werkzeug) y bind `0.0.0.0` | **Crítico** | `app/app.py` | Debug apagado, loopback por defecto, Gunicorn en Docker | Corregido |
| F-05 | A01 Broken Access Control / CWE-306 | Rutas operativas sin autenticación | Alto | `/ping`, `/logs`, `/import` | Sesión + `login_required`, cookie HttpOnly/SameSite | Corregido |
| F-06 | A01 / CWE-22 | Path traversal en `/logs?file=` | Alto | `/logs` | Lista blanca + `safe_join` | Corregido |
| F-07 | A02 Cryptographic Failures / CWE-798 | `SECRET_KEY` hardcodeada | Alto | `app/app.py` | Variable de entorno o aleatoria | Corregido |
| F-08 | A02 / CWE-327, 916 | Contraseñas con MD5 sin sal | Medio | tabla `users` | `generate_password_hash` (scrypt) | Corregido |
| F-09 | A03 / CWE-79 | XSS reflejado por `\|safe` en `/search` | Medio | `templates/result.html` | Autoescape + CSP | Corregido |
| F-10 | A05 / CWE-693, 250 | Sin cabeceras de seguridad; contenedor como root | Medio | respuestas HTTP, `Dockerfile` | CSP, nosniff, X-Frame-Options…; `USER netops` | Corregido |
| F-11 | A06 Componentes vulnerables | 72 avisos (PyYAML 5.3.1, requests 2.25.0, urllib3 1.26.4, Jinja2 3.0.1, gunicorn 20.0.4, Flask 2.0.1, Werkzeug 2.0.1) | Alto/Medio | `app/requirements.txt` | Actualizar y quitar `requests`/`urllib3`/`idna` (no se usaban) | Corregido |

## 4. Validación antes y después
- Evidencia inicial: `evidence/lab5/antes/` (Bandit, pip-audit, Gitleaks, validación manual).
- Pull Request con corrección: rama `security/lab-fsi` → `main` (descripción en `docs/PR_REMEDIACION.md`).
- Evidencia de reescaneo: `evidence/lab5/despues/`.

| Control | Antes | Después |
|---|---|---|
| Bandit (alta / media / baja) | 4 / 4 / 2 | **0 / 0 / 1** (B404, informativo) |
| pip-audit | 72 avisos | **0** |
| Gitleaks | 0 | 0 |
| Validación manual (vulnerable) | 9 de 9 | **0 de 9** |
| Pruebas de regresión (`pytest tests`) | 3 (funcionales) | **8** (incluye un ataque por hallazgo) |

- Riesgo residual y decisión: sin TLS (`NETOPS_COOKIE_SECURE=1` tras publicar con HTTPS), sin límite de intentos de login ni token CSRF (mitigado con SameSite=Lax), un solo usuario sin roles. Se aceptan para este laboratorio y quedan como trabajo futuro.

## 5. Pentest autorizado
- Hipótesis: `/ping` permite inyectar comandos; `/login` permite bypass con SQLi; `/logs` permite leer archivos fuera de `logs/`.
- Entorno aislado: la app corre en `127.0.0.1` (loopback) con base SQLite temporal y usuario ficticio `admin`.
- Solicitudes inocuas: `/ping?host=127.0.0.1;echo INJ42` (solo imprime un marcador), `username=admin' --`, `/logs?file=../app.py`, `/import` con `!!python/object/apply:builtins.len` (sin efectos). Ninguna lee datos reales ni modifica el sistema.
- Resultado línea base: **validado** (9 de 9). Resultado corregida: **no reproducible** (0 de 9; respuestas 400/401/404).
- Recomendación y regresión: `tests/test_app.py` cubre cada ataque; `tools/dast_probe.py` se ejecuta en CI.

## 6. Limitaciones
- Semgrep, CodeQL, Dependabot alerts y ZAP no se ejecutaron en el entorno de desarrollo (sin acceso a `semgrep.dev` ni daemon de Docker); sus resultados se adjuntarán desde Actions. Bandit, pip-audit, Gitleaks y las sondas dirigidas sí se ejecutaron localmente.
- El estado verde de los workflows no implica una aplicación segura (`|| true` en el primer laboratorio).
