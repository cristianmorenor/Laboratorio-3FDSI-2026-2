| ID | Prueba | Resultado | Detalle |
|---|---|---|---|
| VULN-3b | SQLi en /login (bypass de autenticacion) | protegido | HTTP 401 |
| VULN-3 | SQLi en /devices | protegido | filas devueltas: 0 |
| VULN-4 | Inyeccion de comandos en /ping | protegido | HTTP 400 |
| VULN-5 | XSS reflejado en /search | protegido | HTTP 200 |
| VULN-6 | Path traversal en /logs | protegido | HTTP 404 |
| VULN-7 | Deserializacion YAML insegura en /import | protegido | HTTP 400 |
| VULN-8 | Consola del depurador Werkzeug expuesta | protegido | HTTP 404 |
| VULN-9 | Ruta operativa /ping sin autenticacion | protegido | HTTP 401 |
| VULN-10 | Cabeceras de seguridad ausentes | protegido | faltan: ninguna |
