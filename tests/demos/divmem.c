/*
 * divmem.c — Demo: división por cero con el divisor EN MEMORIA (SIGFPE).
 *
 * [POR QUÉ ESTA DEMO EXISTE Y NO ES REDUNDANTE CON divzero.c]
 * `divzero.c` compila a `idiv %rcx`: el divisor está en un REGISTRO. Ese caso
 * lo cura Aegis parcheando un greg.
 *
 * Pero el caso REAL en código compilado es otro: cuando las variables se
 * spilled al stack, GCC emite `idivq -0x20(%rbp)` y el divisor vive en la
 * MEMORIA de la víctima. Ahí no hay ningún registro que parchear, y la cura
 * pasa por resolver la dirección efectiva y escribir un divisor válido ahí
 * antes de re-ejecutar la instrucción.
 *
 * Antes de que esta cura existiera, ese caso caía en `skip`: se saltaba la
 * instrucción y el proceso seguía con un cociente basura, es decir, "curado"
 * en apariencia y roto en realidad. Es la diferencia entre claims y pruebas.
 *
 * [EXPL] `volatile` en el array de entrada no es por el mismo motivo que en
 * divzero.c: aquí hay que FORZAR que el acceso sea a memoria, que es lo que se
 * quiere observar. Un `long b = 0;` promotionado a registro no reproduce nada.
 *
 * [NOTE] Con el motor activo el resultado esperado es `total = 200`, porque el
 * divisor se fuerza a 1 (patch_id 10). Imprimimos el resultado para verificar
 * que la cura fue SEMÁNTICAMENTE correcta: si el motor solo hubiera saltado la
 * instrucción, `total` saldría distinto y el proceso "viviría" mintiendo.
 */
#include <stdio.h>

int main(void)
{
    /* El divisor (índice 1) es cero → la CPU lanza #DE al ejecutar el DIV. */
    volatile long v[2] = { 200, 0 };

    /*
     * Con -O0 esto compila a `idivq -0x20(%rbp)` (spilling al stack);
     * con -O1/-O2 a `idivq 0x8(%rdi)`. Ambas son operandos en MEMORIA, que es
     * justo lo que esta demo existe para cubrir.
     */
    long r = v[0] / v[1];

    printf("resultado = %ld\n", r);
    return 0;
}