# Informe técnico de hallazgos

**Proyecto:** NetOps Automation Console (Secure Product Challenge, opción 2)  
**Integrantes:** Cristian Santiago Moreno Ruiz, David Contreras (equipo G01)  
**Repositorio / commit:** https://github.com/cristianmorenor/Laboratorio-3FDSI-2026-2 — línea base `baseline-lab5`, remediación en `security/lab-fsi`  
**Entorno autorizado:** localhost / runner de GitHub Actions, datos ficticios  
**Fecha:** 2026-10-21  

## Resumen ejecutivo
Los tres riesgos principales de la línea base fueron: (1) **ejecución remota de comandos** en `/ping`, sin autenticación (F-01, F-05); (2) **inyección SQL** que permite saltarse el login (F-02); (3) **deserialización YAML insegura** y depurador de Flask expuesto, que dan control del servidor (F-03, F-04). Se corrigieron los 11 hallazgos críticos, altos y medios; los avisos de dependencias pasaron de 72 a 0 y la validación manual, de 9 de 9 vulnerables a 0 de 9.

## Metodología
Alcance → SAST (Bandit local; Semgrep y CodeQL en Actions) → secretos (Gitleaks) → SCA (pip-audit, Dependabot) → DAST pasivo (ZAP baseline en Actions) → validación manual no destructiva (`tools/dast_probe.py`) → corrección → reescaneo.

## Hallazgo F-01 — Inyección de comandos en `/ping`
- **Título:** Concatenación de `host` en un comando con `shell=True`.
- **Categoría OWASP/CWE:** A03 Injection / CWE-78. Bandit B602.
- **Severidad y justificación:** Crítica. Sin autenticación, cualquier cliente de la red ejecuta comandos con los permisos del servicio.
- **Evidencia minimizada:** `GET /ping?host=127.0.0.1;echo INJ$((40+2))` devuelve `INJ42` (`evidence/lab5/antes/validacion-manual.md`).
- **Impacto:** confidencialidad, integridad y disponibilidad (control total del proceso).
- **Pasos de validación segura:** servidor local en loopback, marcador `echo`, sin leer archivos ni abrir conexiones.
- **Corrección:** commit "fix(app): corregir inyeccion…" — `ipaddress.ip_address`, `subprocess.run([...])` sin shell, timeout y autenticación.
- **Resultado del reescaneo:** `host=127.0.0.1;echo…` → HTTP 400; sondas 0 de 9; test `test_command_injection_blocked`.

## Hallazgo F-02 — Inyección SQL en `/login` y `/devices`
- **Título:** Consultas SQL construidas por concatenación.
- **Categoría OWASP/CWE:** A03 Injection / CWE-89.
- **Severidad y justificación:** Crítica: `username=admin' --` omite la contraseña; `/devices` devuelve toda la tabla con `q=zzz' OR 1=1 --`.
- **Evidencia minimizada:** respuesta `{"ok":true}` con contraseña incorrecta (línea base); 3 filas devueltas por la consulta manipulada.
- **Impacto:** confidencialidad e integridad de la base de datos.
- **Pasos de validación segura:** SQLite temporal con datos ficticios.
- **Corrección:** consultas parametrizadas y comparación con hash con sal.
- **Resultado del reescaneo:** HTTP 401 y 0 filas; test `test_sqli_blocked`.

## Hallazgo F-03 — Deserialización YAML insegura (`/import`)
- **Categoría:** A08 / CWE-502. Bandit B506 + aviso SCA de PyYAML 5.3.1.
- **Severidad:** Crítica (ejecución de código con `yaml.Loader`).
- **Evidencia:** `!!python/object/apply:builtins.len [[1,2,3]]` se acepta con HTTP 200 (función inocua, sin efectos).
- **Corrección:** `yaml.safe_load` + PyYAML 6.0.2 + autenticación. **Reescaneo:** HTTP 400; test `test_yaml_unsafe_tag_rejected`.

## Hallazgos F-04 a F-11 (resumen)
Ver tabla de `docs/SECURITY.md` §3: depurador y bind `0.0.0.0` (F-04), ausencia de autenticación (F-05), path traversal (F-06), secreto hardcodeado (F-07), MD5 sin sal (F-08), XSS (F-09), cabeceras y contenedor root (F-10) y dependencias (F-11), todos corregidos con evidencia en `evidence/lab5/`.

## Reflexión final
Bandit encontró la mayoría de patrones de código (shell, YAML, debug, secreto, MD5) pero **no** la inyección SQL ni el XSS ni el path traversal; esos solo aparecieron con la validación dinámica. Gitleaks no detectó el secreto hardcodeado por su baja entropía. pip-audit cubrió el 100 % de los componentes vulnerables. Ninguna herramienta sustituye a las otras: conviene correr SAST, secretos y SCA en cada Pull Request, DAST sobre un staging propio y mantener pruebas de regresión por cada hallazgo. Pendiente: adjuntar los resultados de Semgrep, CodeQL, Dependabot y ZAP desde Actions, y añadir TLS, límite de intentos de login y CSRF.
