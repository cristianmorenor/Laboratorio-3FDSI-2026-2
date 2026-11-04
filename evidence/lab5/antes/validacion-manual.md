| ID | Prueba | Resultado | Detalle |
|---|---|---|---|
| VULN-3b | SQLi en /login (bypass de autenticacion) | VULNERABLE | HTTP 200 |
| VULN-3 | SQLi en /devices | VULNERABLE | filas devueltas: 3 |
| VULN-4 | Inyeccion de comandos en /ping | VULNERABLE | HTTP 200 |
| VULN-5 | XSS reflejado en /search | VULNERABLE | HTTP 200 |
| VULN-6 | Path traversal en /logs | VULNERABLE | HTTP 200 |
| VULN-7 | Deserializacion YAML insegura en /import | VULNERABLE | HTTP 200 |
| VULN-8 | Consola del depurador Werkzeug expuesta | VULNERABLE | HTTP 200 |
| VULN-9 | Ruta operativa /ping sin autenticacion | VULNERABLE | HTTP 200 |
| VULN-10 | Cabeceras de seguridad ausentes | VULNERABLE | faltan: X-Content-Type-Options, X-Frame-Options, Content-Security-Policy |
