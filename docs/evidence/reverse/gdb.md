# Confirmación dinámica con GDB: `crackme_level2`

**Resumen:** con Ghidra y `objdump` dedujimos cómo valida la clave el programa. Aquí lo comprobamos en ejecución: paramos el programa justo al entrar a `validate_key`, vimos qué recibe y qué devuelve con una clave falsa y con la que calculamos.

- Binario: `crackme_level2` (con símbolos), el mismo del `baseline.txt`.
- Salidas completas: `gdb_clave_fallida.txt` y `gdb_clave_valida.txt`. Los comandos usados están en `gdb_fallida.cmd` y `gdb_valida.cmd`.

## 1. Cómo detuvimos la ejecución en la validación

```text
break validate_key
run AAAA
```

GDB paró en `0x401162` (`validate_key+12`, justo después del prólogo de la función):

```text
Breakpoint 1, validate_key (candidate=0x7fffffffe169 "AAAA") ...
rip   0x401162   <validate_key+12>
```

Esto confirma que `main` sí llama a `validate_key` con nuestro argumento.

## 2. Qué relacionamos con el pseudocódigo de Ghidra

| Lo que vimos en GDB | Lo que dedujimos en Ghidra / `objdump` |
|---|---|
| `rdi` apunta a `"AAAA"` | El primer parámetro de `validate_key` es la clave que escribimos (`clave_usuario`, `argv[1]`). |
| `x/4xb 0x40208b` → `23 51 17 6a` | Es el arreglo `k` de 4 bytes que se repite con `i & 3`. |
| `x/17xb 0x402090` → `65 15 44 23 0e 03 52 3c 66 03 44 2f 0e 63 27 58 15` | Es el arreglo `expected` de 17 bytes: confirma que la longitud esperada es 17 (`0x11`). |
| `finish` y `Value returned is $1 = 0` | `validate_key` devolvió 0 y en `main` el `test eax,eax` / `je` salta a `Invalid license.`. |

## 3. Clave fallida frente a clave válida

| Clave | `rax` al volver a `main` | Salida del programa | Código de salida |
|---|---|---|---|
| `AAAA` | `0x0` | `Invalid license.` | 3 |
| `FDSI-REVERSE-2026` | `0x1` | `License accepted.` y `FLAG{ghidra_plus_gdb}` | 0 |

Con `AAAA` falla por la longitud: tiene 4 caracteres y la función esperaba 17, así que devuelve 0 sin llegar al loop. Con `FDSI-REVERSE-2026` pasa la longitud y los 17 bytes coinciden, el acumulador queda en 0 y `sete al` deja `rax = 1`.

## 4. Qué confirmó GDB que el análisis estático no demostraba

- Que **nuestra clave calculada de verdad funciona** al ejecutar el programa: leyendo el ensamblador solo teníamos una hipótesis.
- Que el valor de retorno de `validate_key` es el que controla el camino de éxito o fallo (0 o 1 en `rax`).
- Que los arreglos `k` y `expected` que leímos en `.rodata` son los mismos que hay en memoria cuando corre el programa.

GDB complementa a Ghidra: Ghidra ayuda a leer y entender el código, y GDB demuestra que lo entendido es correcto sin tener que adivinar.
