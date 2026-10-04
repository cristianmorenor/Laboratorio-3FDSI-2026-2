# Boss Level: `crackme_level2_stripped` (sin símbolos)

**Resumen:** el binario stripped hace exactamente lo mismo que `crackme_level2`, pero sin nombres de funciones ni información de depuración. Encontramos de nuevo `main`, la validación y la función que imprime la FLAG siguiendo el flujo de control, sin usar nombres.

- Binario: `crackme_level2_stripped`. SHA-256 verificado en `baseline.txt`.
- Salidas completas: `stripped_comparacion.txt`, `stripped_start.txt`, `stripped_main.txt`, `stripped_validacion.txt`.

## 1. Qué información desapareció al hacer strip

| | `crackme_level2` | `crackme_level2_stripped` |
|---|---|---|
| `file` | `with debug_info, not stripped` | `stripped` |
| `nm` | `main`, `validate_key`, `reveal_flag`... | `no symbols` |
| `strings` con `validate`, `reveal`, `candidate`, `expected` | aparecen | sin resultados |
| Ejecución con `FDSI-REVERSE-2026` | `License accepted.` + FLAG | `License accepted.` + FLAG |

Se perdieron los **nombres** de funciones y variables y la **información de depuración** (tipos, nombres de parámetros, ruta del `.c`). El **comportamiento** no cambia: la misma clave da la misma FLAG. Strip hace más difícil leer el programa, pero no lo protege.

## 2. Cómo encontramos la lógica sin nombres

**Paso 1: llegar a `main` desde el punto de entrada.** Con `readelf -h` sacamos el entry point (`0x401070`). Al desensamblar ahí (`stripped_start.txt`) vimos:

```text
401084: mov rdi, 0x401267
40108b: call QWORD PTR [rip+0x2f47]
```

El código de arranque de C le pasa en `rdi` la dirección de `main` a `__libc_start_main`, así que **`0x401267` es `main`**.

**Paso 2: encontrar la validación dentro de `main`.** En `stripped_main.txt`, después de comprobar que hay un argumento (`cmp [rbp-0x4],0x2`), el programa hace:

```text
4012ca: mov rdi, rax        ; argv[1], la clave
4012cd: call 401156
4012d2: test eax,eax
4012d4: je 4012f1
```

Una función que recibe la clave y cuyo resultado se prueba con `test eax,eax` para elegir entre éxito y fallo es la de validación (`0x401156`).

**Paso 3: reconocer la función por su comportamiento** (`stripped_validacion.txt`):

- Guarda `0x11` y lo compara con el resultado de `strlen`: la clave mide 17.
- Un loop con `and eax,0x3` (arreglo de 4 bytes cíclico) y varios `xor`.
- Acumula con `or` y termina con `sete al`: devuelve 1 solo si todo coincide.

Es el mismo código que `validate_key`, byte por byte.

**Paso 4: la función de la FLAG.** Si el `test` da distinto de 0, el programa llama a `4011f3`, que imprime caracteres con `putchar`: es `reveal_flag`.

## 3. Tabla de equivalencias

| Dirección | Con símbolos | En el stripped (nombre que le daríamos) |
|---|---|---|
| `0x401267` | `main` | `main` (identificada desde `_start`) |
| `0x401156` | `validate_key` | `validar_clave` |
| `0x4011f3` | `reveal_flag` | `imprimir_flag` |

## 4. Qué aprendimos

- Quitar símbolos con `strip` **no esconde la lógica**: se reconstruye con referencias, flujo de control y patrones.
- Las direcciones y el código son idénticos, solo cambian los nombres. Con Ghidra bastaría renombrar `FUN_00401156` y seguir.
- Si un secreto está en el binario, strip no lo protege.
