# Fase D — Detección (Blue Team)

## Correlación de eventos

| Hora UTC | Acción Red Team | Evidencia en access.log | Conclusión |
|---|---|---|---|
| 02:00:51 | Nmap -sV puerto 80 | 6 líneas en 1 segundo, User-Agent "Nmap Scripting Engine", 3 respuestas 404 | Reconocimiento automatizado detectado por ráfaga y firma de User-Agent |
| 02:00:51 | curl GET / y HEAD /device-inventory.txt | 200 y 200, User-Agent "curl/8.20.0" | Actor distinto identificado por User-Agent, correlación confirmada |
| 02:14–02:17 | ZAP Manual Explore (Firefox) | 5 peticiones con User-Agent Firefox real, 1x404 en /favicon.ico | Tráfico de exploración pasiva, no ataque; el 404 es ruido normal del navegador |

## Regla de detección

Una IP que genera 5 o más respuestas 404 en una ventana de 5 minutos se marca como sospechosa de reconocimiento automatizado.

Comando de verificación:
sudo awk '$9 ~ /404/ {print $1, $4, $7, $9}' /var/log/nginx/access.log.1 | sort | uniq -c | sort -nr

## Limitación observada

En esta prueba, el escaneo de Nmap generó solo 3 respuestas 404 en el mismo segundo, sin alcanzar el umbral de 5. Esto representa un falso negativo de la regla. Se podría reforzar correlacionando el User-Agent ("Nmap Scripting Engine" es una firma clara) o bajando el umbral a 3 eventos en 1 minuto para escaneos rápidos.
