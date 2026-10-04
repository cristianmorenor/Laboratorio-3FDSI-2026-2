# Nivel 2: reconstruir la validación de `crackme_level2`

**Resumen:** esta vez la clave no aparece en texto plano. El programa pide una "license key", revisa que tenga 17 caracteres y que cada byte, transformado con un XOR, coincida con un arreglo guardado en el binario. Con Ghidra reconstruimos el algoritmo, calculamos la clave al revés y obtuvimos la FLAG.

**Clave:** `FDSI-REVERSE-2026`

**FLAG:** `FLAG{ghidra_plus_gdb}`

- Binario: `crackme_level2` (ELF x86-64, con símbolos). SHA-256 verificado en `baseline.txt`.
- Herramientas: ejecución directa, `objdump`, `objdump -s -j .rodata` y Ghidra. No se consultó el código fuente.
- Salidas completas: `level2_main.txt`, `level2_validate.txt`, `level2_rodata.txt`, `level2_solver.txt`, `level2_flag.txt`.

## 1. Qué observamos al principio

| Comando | Qué respondió | Código de salida |
|---|---|---|
| `./crackme_level2` | Banner y `Uso: ./crackme_level2 <license-key>` | 1 |
| `./crackme_level2 prueba` | `Invalid license.` | 3 |

Hay un camino de éxito (`License accepted.`) y uno de fallo, igual que en el nivel 1. Pero ahora `strings` no muestra ninguna clave.

## 2. Cómo encontramos la función de validación

En `main` (`level2_main.txt`) vimos esta secuencia:

1. `cmp [rbp-0x4],0x2`: comprueba que haya exactamente un argumento.
2. `call 401156 <validate_key>`: le pasa `argv[1]` (la clave) en `rdi`.
3. `test eax,eax` y `je 4012f1`: si devuelve 0, salta a `Invalid license.` y sale con 3.
4. Si no, imprime `License accepted.` y llama a `reveal_flag`.

Por eso `validate_key` es la función que decide todo.

## 3. Qué hace `validate_key`

**Longitud.** Guarda `0x11` en una variable local y la compara con `strlen(clave)`. Si no son iguales, devuelve 0. **La clave tiene 17 caracteres.**

**Transformación por byte.** Para cada posición `i` de 0 a 16:

- toma `clave[i]`,
- lo combina con XOR con `k[i & 3]`, donde `k` es un arreglo de 4 bytes (`23 51 17 6a`) que se repite cíclicamente,
- ese resultado se compara con `expected[i]` (arreglo de 17 bytes en `.rodata`, dirección `0x402090`) usando otro XOR,
- y todas las diferencias se juntan con `OR` en un acumulador.

Al final devuelve 1 solo si el acumulador quedó en 0, es decir, si **los 17 bytes coincidieron**.

Los arreglos los sacamos con `objdump -s -j .rodata` (`level2_rodata.txt`):

```text
k        (0x40208b): 23 51 17 6a
expected (0x402090): 65 15 44 23 0e 03 52 3c 66 03 44 2f 0e 63 27 58 15
```

## 4. Pseudocódigo propio

```text
validar(clave):
    si longitud(clave) != 17:
        devolver 0
    diferencias = 0
    para i desde 0 hasta 16:
        b = k[i % 4] XOR clave[i]
        diferencias = diferencias OR (expected[i] XOR b)
    devolver 1 si diferencias == 0, si no 0
```

## 5. Cómo reconstruimos la clave

XOR se deshace con la misma operación. Si la condición válida es `k[i%4] ^ clave[i] == expected[i]`, entonces:

```text
clave[i] = expected[i] XOR k[i % 4]
```

Con un script corto (`level2_solver.txt`) dio `FDSI-REVERSE-2026`. A mano, el primer carácter: `0x65 XOR 0x23 = 0x46 = 'F'`.

## 6. Cómo lo confirmamos

```text
$ ./crackme_level2 FDSI-REVERSE-2026
=== FDSI CrackMe Level 2 ===
Hint: static + dynamic analysis.
License accepted.
FLAG{ghidra_plus_gdb}
```

La confirmación en ejecución con GDB está en `gdb.md`.

## 7. Evidencia en Ghidra

Captura del decompilador de `validate_key` con variables renombradas (`clave_usuario`, `longitud_esperada`, `acumulador_diff`, `byte_transformado`): `screenshots/level2_ghidra.png`.

Ghidra nos dejó ver el `if` de la longitud y el loop con el XOR en pocas líneas, mientras que con `objdump` había que seguir los registros a mano.

## 8. Qué tiene de inseguro este diseño

- **El algoritmo y los datos están en el binario.** Quien tenga el ejecutable puede reconstruir la clave sin ejecutarlo, como hicimos nosotros.
- **XOR con clave fija no es criptografía.** Es reversible a propósito, y `k` viaja junto a `expected`.
- **Ocultar la clave no es protegerla.** Que no salga en `strings` solo retrasa a quien analiza.

**Para desarrollar seguro:** no validar licencias solo en el cliente con secretos incrustados; usar verificación en un servidor o firmas digitales (la clave pública puede ir en el binario sin comprometer la privada).
