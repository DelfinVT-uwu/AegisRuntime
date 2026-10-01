/*
 * null_deref.c — Demo: escritura a puntero nulo (SIGSEGV).
 *
 * Responsabilidad: provocar un fallo de memoria que AegisRuntime debe
 * sobrevivir, saltándose la instrucción que falló.
 *
 * [EXPL] Por qué un puntero REAL a NULL y no `*(int*)0`: el compilador sabe
 * que desreferenciar un literal nulo es UB y puede eliminar la escritura
 * entera (dead store elimination). Con un puntero cargado en runtime desde
 * una variable `volatile` no puede saber nada y conserva el `mov`.
 *
 * [NOTE] La mitigación de Fase 1 es "skip": se salta la instrucción que
 * faultó, así que `v` conserva su valor original (42) y el programa sigue
 * como si el store nunca hubiera ocurrido. Eso es coherente con el contrato
 * de la regla 3 (skip deref nula) documentada en ARCHITECTURE.md §4.
 *
 * [WARN] Esto NO es la Fase 2. Aquí la escritura se pierde. La Fase 2
 * redirige el acceso a la shadow zero-page, de modo que el store sí ocurre
 * (en una página de ceros) y el programa sigue su curso sin pérdida.
 */
#include <stdio.h>

int main(void)
{
    int v = 42;
    volatile int *p = (int *)0;   /* NULL real, invisible al optimizador */

    *p = v;                       /* SIGSEGV: escritura en la página 0 */

    printf("v=%d\n", v);
    return 0;
}