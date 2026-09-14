## Modelo de amenazas STRIDE — Lab 3

| ID | STRIDE | Hipótesis técnica | Validación |
|---|---|---|---|
| H1 | Information Disclosure | HTTP permite observar en tránsito el contenido del inventario de dispositivos y catálogo de scripts | Captura PCAP filtrada (tcpdump) |
| H2 | Information Disclosure | Headers y respuestas de Nginx revelan versión del servidor y rutas internas | `curl -I` y reporte ZAP pasivo |
| H3 | Repudiation | Sin correlación temporal, no se puede atribuir una solicitud a un actor específico | Comparar comando ejecutado vs. `access.log` |
| H4 | Tampering | Sin TLS, un intermediario podría alterar el tráfico (no se ejecuta MITM real) | Demostrar ausencia de protección, sin interceptar terceros |

### Registro de riesgos
| Hipótesis | Estado | Notas |
|---|---|---|
| H1 | Pendiente | Se corrige parcialmente en Fase E (headers), TLS completo queda para Lab 4 |
| H2 | Pendiente | `server_tokens off` en Fase E oculta versión |
| H3 | Aceptado para Lab 3 | Requiere autenticación/identidad, entra en Lab 4 |
| H4 | Aceptado para Lab 3 | Requiere HTTPS, entra en Lab 4 |
