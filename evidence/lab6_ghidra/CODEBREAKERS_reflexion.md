# CODEBREAKERS — El misterio del código oculto

**Equipo:** G01 — Cristian Santiago Moreno Ruiz, David Contreras
**Curso:** Fundamentos de Seguridad de la Información (FDSI) — Eciciencia 2026
**Fecha:** 2026-11-04
**Alcance:** únicamente el archivo `reto_codebreakers_linux_x64` entregado por el monitor, en entorno de laboratorio. Sin sistemas, cuentas ni claves de terceros.

> Por indicación de la guía, la contraseña final no se publica en este repositorio; se presentó directamente al monitor.

## 1. Qué hicimos

| Paso | Acción | Evidencia |
|---|---|---|
| 1 | Importar el ELF x86-64 en Ghidra y ejecutar el análisis automático | Captura A |
| 2 | `Search → For Strings`: aparecen `ACCESO CONCEDIDO`, `ACCESO DENEGADO` y la FLAG | Captura de cadenas |
| 3 | Seguir las referencias (XREF) de esas cadenas hasta la función `main` | XREF `main:00101a67` |
| 4 | Localizar en `.rodata` la clave AES-256 (32 bytes) y el IV (16 bytes) | Captura B1 (`00102300`) |
| 5 | Localizar el texto cifrado `aes_ct` (16 bytes) | Captura en `001020e0` |
| 6 | Leer el Decompiler: `main` descifra `aes_ct` y compara con `strcmp` | Captura B2 |
| 7 | Descifrar `aes_ct` con AES-256-CBC (CyberChef) y obtener la contraseña | Captura de CyberChef |
| 8 | Validar la contraseña con el verificador de la guía | `ACCESO CONCEDIDO` + FLAG |

## 2. Cómo funciona la validación

El programa no guarda la contraseña en texto plano. En su lugar:

1. Descifra `aes_ct` con AES-256-CBC usando una clave y un vector de inicialización (IV) incluidos en el propio ejecutable.
2. Compara con `strcmp` la entrada del usuario contra el texto descifrado.
3. Si `strcmp` devuelve `0`, imprime `ACCESO CONCEDIDO` y la FLAG; de lo contrario, `ACCESO DENEGADO`.

La contraseña **no aparece como cadena** en el binario: se calcula en tiempo de ejecución, por eso la búsqueda de cadenas por sí sola no la muestra. La clave y el IV sí están guardados como bytes sin terminador nulo, por lo que la búsqueda de cadenas de Ghidra no los lista y hubo que ir directamente a su dirección en `.rodata`.

## 3. Qué es cada pieza

- **Clave AES-256:** 32 bytes; es la llave de cifrado y descifrado.
- **IV (vector de inicialización):** 16 bytes; se combina (XOR) con el primer bloque en modo CBC. No es secreto, pero debe ser el mismo para descifrar. En el Decompiler aparece como dos constantes de 8 bytes combinadas con `^`.
- **Texto cifrado (`aes_ct`):** 16 bytes, un solo bloque AES.
- **Relleno PKCS#7:** tras descifrar quedan bytes de relleno al final, que se ignoran.

## 4. Reflexión final

**¿Por qué no es seguro guardar una contraseña fija y reutilizable dentro de un programa distribuido a los usuarios?**

Porque quien recibe el ejecutable recibe también todo lo necesario para recuperarla. Aunque la contraseña esté cifrada con AES-256 —un algoritmo robusto—, la clave de descifrado y el IV viajan dentro del mismo binario. Con una herramienta gratuita como Ghidra, en pocos minutos y sin acceso al código fuente, se localizan los tres datos y se descifra la contraseña. El cifrado solo dificulta el análisis; no elimina el problema. La fortaleza del algoritmo no compensa que el secreto esté al alcance del atacante.

**Cómo se evitaría:**

- No incrustar secretos reutilizables en el cliente ni en el ejecutable.
- Guardar únicamente un **hash con sal** de la contraseña (por ejemplo `scrypt`, `bcrypt` o Argon2) y comparar hashes. Así no existe nada que descifrar. Es lo que aplicamos en el Laboratorio 5 al reemplazar MD5 por `scrypt`.
- Mover la validación a un **servidor** bajo control del propietario, en lugar de validar en la máquina del usuario.
- Gestionar secretos mediante variables de entorno o un gestor de secretos, y rotarlos si se exponen.

**Relación con el Laboratorio 5:** es el mismo patrón que el hallazgo F-07 (`SECRET_KEY` hardcodeada, CWE-798): un secreto dentro del código o del binario siempre puede ser extraído. Y, como en ese laboratorio, ninguna herramienta basta por sí sola: aquí hizo falta combinar análisis de cadenas, referencias cruzadas, lectura del descompilado y descifrado manual.

## 5. Herramientas

Ghidra (importación, búsqueda de cadenas, XREF, Decompiler), CyberChef (descifrado AES-256-CBC), verificador auxiliar de la guía.
