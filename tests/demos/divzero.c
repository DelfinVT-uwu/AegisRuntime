/*
 * divzero.c — Demo: división por cero (SIGFPE).
 *
 * Responsabilidad: provocar un fallo que AegisRuntime debe curar sin tocar
 * una sola línea del código de la aplicación.
 *
 * [EXPL] `volatile` es OBLIGATORIO en las dos variables. Sin él el compilador
 * ve `a / b` con b = 0 constante y lo resuelve en tiempo de compilación
 * (optimización asumida o diagnóstico), así que en -O2 puede no emitir
 * ninguna instrucción `div` en runtime y la demo no reproduce nada. Con
 * -O0 funciona igual, pero queremos que la demo sea robusta a cualquier
 * nivel de optimización.
 *
 * [NOTE] El resultado esperado con el motor activo es `a / 1 == a`, porque
 * la regla de curación fuerza el divisor a 1 (ver engine.rs, patch_id 1).
 * Impresionamos el resultado para PROBAR que la cura fue semánticamente
 * correcta, no solo que el proceso dejó de morir.
 */
#include <stdio.h>

int main(void)
{
    volatile long a = 100;
    volatile long b = 0;

    /* SIGFPE: el hardware divide por cero antes de que el código pueda
     * comprobarlo. gcc emite `idiv %rcx` con RCX = 0. */
    long r = a / b;

    printf("resultado = %ld\n", r);
    return 0;
}