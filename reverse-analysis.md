# Analisis: Reverse Engineering CTF (Lab 4)

Evidencia completa en `docs/evidence/reverse/`.

| Nivel | Resultado |
|---|---|
| Nivel 1 | Contrasena `REDTEAM-101`, FLAG `FLAG{strings_are_evidence}` |
| Nivel 2 | Clave `FDSI-REVERSE-2026`, FLAG `FLAG{ghidra_plus_gdb}` |
| Boss (stripped) | Misma logica y clave, encontrada desde `_start` sin nombres |

## Preguntas de analisis

**1. Que informacion obtuvimos sin ejecutar el binario?**
Formato y arquitectura (`file`, `readelf`), hash, mensajes, nombres de funciones y la ruta del `.c` (`strings`). En el nivel 1 salio la contrasena tal cual. En el nivel 2, con el ensamblador y `.rodata`, sacamos la longitud (17), el XOR por byte y los arreglos, y calculamos la clave.

**2. Por que una contrasena compilada como string es inseguro?**
El binario lo tiene cualquiera que lo reciba y `strings` la muestra sin ejecutarlo. Es una credencial incrustada (CWE-798): no se puede cambiar sin recompilar ni ocultar de quien tiene el archivo.

**3. Que cambio entre level2 y level2_stripped?**
Desaparecieron los nombres de funciones y la informacion de depuracion. El comportamiento y el codigo son iguales: misma clave, misma FLAG, mismas direcciones.

**4. Que ventaja tuvo Ghidra sobre objdump?**
Ghidra decompila a C, muestra el `if` de la longitud y el loop con el XOR en pocas lineas y deja renombrar variables y seguir referencias. Con objdump hay que seguir registros y saltos a mano.

**5. Que confirmo GDB que lo estatico no demostraba?**
Que la clave calculada funciona al ejecutar: `validate_key` devolvio 0 con `AAAA` y 1 con `FDSI-REVERSE-2026`, y que los arreglos `k` y `expected` de `.rodata` son los que hay en memoria al correr.

**6. Por que Burp Suite no es una herramienta de ingenieria inversa de binarios?**
Burp es un proxy que intercepta y modifica trafico HTTP. Solo ve lo que viaja por la red; no desensambla ni decompila ejecutables. Ghidra y GDB analizan el binario, Burp la comunicacion web.

**7. Que controles de desarrollo evitarian secretos embebidos?**
- No guardar secretos en el codigo: variables de entorno o gestor de secretos.
- Validar licencias en un servidor o con firmas digitales.
- Guardar solo hashes con sal (bcrypt, argon2), no la contrasena.
- Escanear secretos en el repo y en CI (gitleaks, trufflehog) y hacer revision de codigo.
- Recordar que ofuscar (XOR, strip) no es proteger.
