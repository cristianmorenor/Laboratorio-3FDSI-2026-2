# PR: remediación de seguridad (security/lab-fsi → main)

## Qué cambia
Corrige 11 hallazgos de la línea base (`baseline-lab5`): inyección de comandos y SQL, YAML inseguro, depurador expuesto, rutas sin autenticación, path traversal, secreto hardcodeado, MD5, XSS, cabeceras/contenedor root y dependencias vulnerables. Integra el kit AppSec (Semgrep, Gitleaks, ZAP), Dependabot y pruebas de regresión.

## Evidencia antes / después
| Control | Antes | Después |
|---|---|---|
| Bandit alta/media/baja | 4/4/2 | 0/0/1 |
| pip-audit | 72 | 0 |
| Validación manual | 9/9 vulnerable | 0/9 |
| pytest | 3 | 8 |

Detalle: `docs/SECURITY.md`, `docs/REPORTE_HALLAZGOS.md`, `evidence/lab5/`.

## Checklist de seguridad
- [x] Descripción y alcance definidos.
- [x] Sin credenciales, tokens ni `.env` (Gitleaks: 0 hallazgos; secretos solo por variables de entorno).
- [x] SAST interpretado (Bandit; Semgrep/CodeQL pendientes de ejecución en Actions).
- [x] Dependencias revisadas (pip-audit 72 → 0; Dependabot configurado).
- [x] Autenticación y autorización revisadas (`login_required` en rutas operativas).
- [x] Pruebas funcionales y de regresión (`pytest tests`).
- [x] DAST solo sobre entorno propio (localhost); ZAP en `dast-local.yml`.
- [x] Hallazgos, mitigaciones y evidencias vinculados.

## Riesgo residual
Sin TLS, sin límite de intentos de login ni CSRF token, usuario único.
