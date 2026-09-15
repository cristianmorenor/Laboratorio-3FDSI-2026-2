# Reflexión individual — Cristian Santiago Moreno Ruiz (Red Team)

En este laboratorio asumí el rol de atacante (Red Team). Mi trabajo
consistió en realizar reconocimiento sobre la aplicación web publicada
por mi compañero, usando herramientas como Nmap, curl y OWASP ZAP en
modo pasivo, sin explotar ninguna vulnerabilidad ni modificar el
servicio.

Lo que pude observar es que, al no existir cifrado en la comunicación
(HTTP sin TLS), toda la información que viaja entre el cliente y el
servidor queda expuesta en texto plano: contenido, rutas y headers
pueden ser observados directamente por cualquiera que capture el
tráfico. Esto evidenció de forma práctica por qué HTTP por sí solo no
garantiza confidencialidad ni integridad de los datos.

La mayor dificultad que tuve no fue técnica sino logística: coordinar
la sesión en tiempo real por Zoom para ejecutar el ataque mientras mi
compañero capturaba el tráfico. No tenía experiencia previa con
control remoto entre computadores, lo que hizo más lenta la
coordinación inicial, aunque finalmente logramos ejecutar las pruebas
de forma simultánea.

Respecto a las amenazas STRIDE, considero que la que debe priorizarse
en el Laboratorio 4 es Tampering e Information Disclosure asociadas
a la falta de cifrado: al implementar HTTPS se protege la
confidencialidad e integridad del tráfico, cerrando la posibilidad de
que un intermediario observe o altere la comunicación sin ser
detectado. Esto, junto con mecanismos de autenticación y roles, es la
base necesaria para avanzar hacia una aplicación realmente segura.
