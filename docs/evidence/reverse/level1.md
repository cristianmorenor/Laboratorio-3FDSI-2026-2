# Nivel 1: encontrar cómo valida la contraseña `crackme_level1`

**Resumen:** el programa pide una contraseña por argumento y la compara con una cadena que está escrita en texto claro dentro del propio binario. Con `strings` y `objdump` la encontramos sin ejecutarlo, la probamos y obtuvimos la FLAG.

**FLAG:** `FLAG{strings_are_evidence}`

**Contraseña:** `REDTEAM-101`

- Binario: `crackme_level1` (ELF x86-64, con símbolos). SHA-256 verificado contra la guía (ver `baseline.txt`).
- Herramientas: ejecución directa, `strings` y `objdump`. No se consultó el código fuente.
- Salidas completas de los comandos: carpeta `level1_raw/`.

## 1. Qué observamos al principio

Antes de analizar nada, ejecutamos el programa con datos falsos:

| Comando | Qué respondió | Código de salida |
|---|---|---|
| `./crackme_level1` | Un banner y `Uso: ./crackme_level1 <password>` | 1 |
| `./crackme_level1 prueba` | `Access denied.` | 2 |

De aquí sacamos dos cosas: el programa espera la contraseña como **argumento**, y tiene mensajes distintos para "usaste mal el programa" y "contraseña incorrecta". Si hay un mensaje de fallo, tiene que haber uno de éxito.

## 2. Qué hipótesis formulamos

Al mirar `strings` (siguiente sección) vimos la función `strcmp`, los mensajes de acceso y una cadena rara: `REDTEAM-101`. Con eso planteamos:

> El programa compara con `strcmp` lo que escribimos contra una cadena guardada dentro del binario. Creemos que esa cadena es `REDTEAM-101`. Si coinciden, muestra `Access granted.` y llama a `print_flag`.

Era solo una hipótesis: `strings` demuestra que la cadena **existe**, no que sea la que se compara.

## 3. Qué evidencia encontramos

### Con `strings -n 5 crackme_level1`

Esta herramienta lista los textos legibles que hay dentro del archivo, sin ejecutarlo. Lo que nos llamó la atención:

- `strcmp`: el programa compara cadenas.
- `Access granted.` y `Access denied.`: hay un camino de éxito y uno de fallo.
- `REDTEAM-101`: aparece junto a los mensajes y no parece de ninguna biblioteca.
- `print_flag`: hay una función que imprime la FLAG.

### Con `objdump -d -M intel crackme_level1`

Para no quedarnos con una sospecha, miramos el ensamblador de `main`. Esto es lo que hace, en orden:

1. Comprueba que hayamos pasado exactamente un argumento. Si no, imprime el uso y sale con 1.
2. Llama a `strcmp` comparando nuestro argumento con el texto guardado en la dirección `0x402004`.
3. Si `strcmp` no devuelve 0 (las cadenas son distintas), salta al mensaje `Access denied.` y sale con 2.
4. Si devuelve 0, imprime `Access granted.`, llama a `print_flag` y sale con 0.

Con `objdump -s -j .rodata` vimos qué hay en `0x402004`: los bytes `52 45 44 54 45 41 4d 2d 31 30 31`, que en ASCII son `REDTEAM-101`. Con esto la hipótesis ya no es una corazonada: el código compara nuestro argumento justamente contra esa cadena.

## 4. Cómo funciona la validación (en pseudocódigo)

```text
si no me pasan exactamente un argumento:
    mostrar uso y salir con 1
si argumento == "REDTEAM-101":
    mostrar "Access granted."
    imprimir la FLAG
    salir con 0
si no:
    mostrar "Access denied."
    salir con 2
```

## 5. Cómo confirmamos la hipótesis

La probamos en ejecución:

```text
$ ./crackme_level1 REDTEAM-101
=== FDSI CrackMe Level 1 ===
Access granted.
FLAG{strings_are_evidence}
exit code: 0
```

Salió lo que habíamos predicho con el ensamblador, incluido el código de salida 0, que hasta ese momento solo habíamos deducido leyendo el código.

## 6. Cómo obtuvimos la FLAG (y por qué no salía en `strings`)

La FLAG la imprimió el programa, pero **nunca apareció en la salida de `strings`**. Para entender por qué, miramos `print_flag`:

- Guarda 26 bytes en la pila, que no son texto legible.
- Recorre esos bytes con un contador y a cada uno le aplica un XOR con el valor `0x5a`.
- Imprime el resultado carácter a carácter con `putchar`.

Es decir, la FLAG está guardada "disfrazada" y solo se reconstruye cuando el programa corre. Como comprobación, decodificamos los 26 bytes por separado con un script y dio la misma FLAG. Dos ejemplos a mano: `0x1c XOR 0x5a = 'F'` y `0x16 XOR 0x5a = 'L'`.

## 7. Por qué `strings` puede revelar secretos

`strings` busca cualquier secuencia de caracteres imprimibles dentro del archivo. Cuando un programador escribe una contraseña como texto en su código, el compilador la deja tal cual en el binario, y `strings` la muestra sin necesidad de ejecutar nada. Eso pasó con `REDTEAM-101`.

La FLAG se salvó de `strings` solo porque estaba cifrada con XOR. Pero eso es un disfraz muy débil: la clave (`0x5a`) está en el mismo programa, así que cualquiera que lo desensamble la recupera.

## 8. Qué tiene de inseguro este diseño

- **Contraseña escrita en el código (hard-coded credential, CWE-798).** El secreto viaja dentro del binario, y el binario lo tiene cualquiera que lo reciba. Quien lo obtenga puede sacar la contraseña sin ejecutarlo.
- **Ofuscar no es cifrar.** El XOR con una clave fija que va en el mismo archivo solo retrasa unos minutos a quien analiza.
- **Se filtra más información de la necesaria.** El binario conserva nombres de funciones (`print_flag`) y datos de depuración, lo que ayuda a entender el programa.

**Qué aprendimos para desarrollar seguro:** no hay que meter secretos dentro de lo que se distribuye. Una validación de este tipo debería apoyarse en algo que no esté en el artefacto, como una comprobación en un servidor, o almacenar solo un hash con sal en vez de la contraseña. (Esta última recomendación es la práctica habitual para este tipo de fallo; no sale de este binario en particular.)
