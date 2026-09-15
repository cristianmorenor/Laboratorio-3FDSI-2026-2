# Laboratorio 3 — NetOps Automation Console

Prototipo del Secure Product Challenge (FDSI), Opción 2: Ejecución
controlada de scripts remotos en equipos de red. Aplicación web
mínima publicada por HTTP y sin autenticación, con ciclo completo
de construcción, ataque, detección, corrección y verificación.

## Equipo (G01)

| Integrante | Rol en Lab 3 |
|---|---|
| David Contreras | Blue Team |
| Cristian Santiago Moreno Ruiz | Red Team |

## Arquitectura

- **Ubuntu Server LTS**: aloja el sitio con Nginx (puerto 80),
  firewall UFW limitado a la red del laboratorio, telemetría en
  access.log/error.log.
- **Kali Linux**: estación de reconocimiento (Nmap, curl, ZAP pasivo).
- Ambas VMs conectadas por red Host-Only (192.168.56.0/24) para
  comunicarse entre sí, con adaptador NAT adicional para acceso
  a internet (clonar repo, instalar paquetes).

Diagrama completo con fronteras de confianza: `diagrams/dfd-lab3.png`

## Variables usadas

```bash
export TARGET_IP=192.168.56.101
export TARGET_URL=http://$TARGET_IP
export LAB_CIDR=192.168.56.0/24
```

## Procedimiento de reproducción

1. **Publicar el sitio** (Ubuntu): Nginx instalado y configurado con
   virtual host en `/etc/nginx/sites-available/netops-secure-challenge`,
   contenido en `/var/www/netops-secure-challenge/`.
2. **Restringir acceso**: firewall UFW permitiendo solo el CIDR del
   laboratorio en el puerto 80, más SSH.
3. **Reconocimiento** (Kali): `nmap -Pn -sV -p 80 $TARGET_IP`, `curl`
   a la raíz y a los archivos públicos, exploración pasiva con
   OWASP ZAP (Manual Explore, sin Active Scan).
4. **Captura de tráfico** (Ubuntu, simultánea al ataque):
   `tcpdump -i any -nn -s0 -w evidence/blue/lab3-http.pcap 'tcp port 80'`
5. **Detección** (Ubuntu): correlación de `access.log` con la
   actividad de Red Team, regla de detección basada en respuestas
   404 repetidas — ver `evidence/blue/deteccion-fase-d.md`.
6. **Corrección** (Ubuntu): hardening en Nginx —
   `server_tokens off`, headers de seguridad
   (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`),
   bloqueo de rutas ocultas (`location ~ /\. { deny all; }`).
7. **Verificación**: repetición de Nmap y curl contra el sitio ya
   corregido — ver `evidence/retest/`.


## Comparación antes/después (hardening)

| Aspecto | Antes (Fase C) | Después (Fase F) |
|---|---|---|
| Versión del servidor | `nginx 1.28.3 (Ubuntu)` | `nginx` (oculta) |
| Headers de seguridad | Ausentes | Presentes (nosniff, DENY, no-referrer) |
| Ruta `.git/config` | Sin evaluar | `403 Forbidden` |

## Riesgos pendientes para el Laboratorio 4

Ver `risk-register.md`: H3 (Repudiation) y H4 (Tampering) requieren
autenticación, identidad y HTTPS — explícitamente fuera de alcance
del Lab 3, según el límite pedagógico de la guía.

## Tag de entrega

```bash
git tag lab-3
```
