# Reflexión individual — David Contreras (Blue Team)

En este laboratorio construimos una aplicación web pública por HTTP,
donde asumí el rol de defensor (Blue Team). Mi parte incluyó publicar
el sitio con Nginx, capturar el tráfico durante el reconocimiento de
mi compañero (Red Team), revisar los logs generados y aplicar
correcciones de hardening.

Un hallazgo técnico que me llamó la atención fue observar en el
access.log cómo el propio escaneo de Nmap (con la opción -sV) generó
peticiones extrañas como /nmaplowercheck, /HNAP1 o /evox/about, todas
en el mismo segundo y con el mismo User-Agent "Nmap Scripting Engine".
Antes de revisarlo con calma, esas líneas parecían intentos de ataque
reales, pero en realidad eran sondas automáticas de la propia
herramienta tratando de identificar el servicio. Esto me hizo entender
la importancia de correlacionar evidencia (IP, hora, User-Agent) antes
de sacar conclusiones sobre un evento.

La mayor dificultad no fue técnica sino de coordinación: al trabajar
con el disco compartido por turnos, tuvimos que organizar una sesión
en vivo (videollamada con control remoto) para que el ataque y la
captura de tráfico ocurrieran al mismo tiempo, ya que ambas evidencias
debían corresponder al mismo instante para tener sentido.

Como corrección, apliqué hardening básico en Nginx: deshabilité la
exposición de la versión del servidor (server_tokens off) y agregué
headers de seguridad (X-Content-Type-Options, X-Frame-Options,
Referrer-Policy). Sin embargo, esto no resuelve el riesgo de fondo:
el tráfico sigue viajando sin cifrar. Por eso considero que la
amenaza que debe priorizarse en el Laboratorio 4 es la exposición de
información en tránsito (Information Disclosure) mediante HTTPS,
junto con Repudiation, ya que sin autenticación no podemos atribuir
con certeza una acción a un usuario específico.
