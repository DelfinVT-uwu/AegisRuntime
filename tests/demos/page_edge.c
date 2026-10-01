/*
 * page_edge.c — Demo: DIV por cero pegado al FINAL de una página.
 *
 * [POR QUÉ EXISTE]
 * Regresión del modo de fallo más grave que tenía el runtime. El motor antes
 * leía la instrucción con `slice::from_raw_parts(rip, 15)`, es decir, leía
 * 15 bytes FIJOS desde RIP. Con el DIV a 2 bytes del final de su página, esa
 * ventana cruzaba a la página siguiente (PROT_NONE) y provocaba un SIGSEGV
 * DENTRO DEL handler de señal, que el kernel no puede recuperar: forzaba
 * SIG_DFL y mataba el proceso sin log, sin telemetría y sin el abort
 * controlado. El runtime que debía proteger al proceso era el que lo mataba,
 * y sin dejar rastro.
 *
 * [LO QUE SE COMPRUEBA AHORA]
 * Que el runtime cure el fallo incluso con la instrucción al borde de la
 * página, y que la página siguiente (PROT_NONE) la maneje con limpieza si
 * algún día se alcanza. La cura ya no exige 15 bytes legibles: la capa C
 * copia el prefijo legible (aquí 3 bytes: F7 F1 C3) y el decodificador
 * falla cerrado ante un buffer corto en vez de leer de una página inexistente.
 *
 * [TRUCO DEL DISEÑO]
 * Después del DIV ponemos un `ret` (0xC3) DENTRO de la misma página. Sin él,
 * al curar la división la CPU caería directamente sobre la guard page y el
 * proceso moriría — no por un fallo del runtime, sino porque el demo acaba
 * en mitad de una página. Con el `ret`, el camino curado
 * termina de verdad y el proceso sale con 0.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

/* Reserva DOS páginas y vuelve la segunda INACCESIBLE (guard page).
 *
 * [WHY] Una sola página no vale: el kernel puede devolver una dirección en
 * medio de un VMA mayor, así que la página siguiente acaba mapeada y la
 * lectura de 15 bytes devuelve ceros sin fallar. El bug queda oculto y la
 * demo "pasa" por casualidad. La guard page lo hace determinista — y es el
 * caso real: guardas de pila, chunks de malloc grandes, `-fstack-clash-
 * protection`, JIT compilados.
 */
static unsigned char *alloc_guarded_page(long ps)
{
    unsigned char *p = mmap(NULL, (size_t)(ps * 2), PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return NULL;
    /* La segunda página es una hoja de trampolín: sin acceso para nadie. */
    if (mprotect(p + ps, (size_t)ps, PROT_NONE) != 0)
        return NULL;
    return p;
}

int main(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    unsigned char *page = alloc_guarded_page(ps);
    if (!page) {
        fprintf(stderr, "no se pudo mapear la página\n");
        return 1;
    }

    /* DIV ECX (F7 F1) + RET (C3), ocupando los últimos 3 bytes de la
     * primera página. El RET es imprescindible: sin él, al curar la división
     * la CPU caería sobre la guard page y el proceso moriría —no por un fallo
     * del runtime, sino porque el demo acaba a mitad de una página. */
    unsigned char *code_at = page + ps - 3;
    code_at[0] = 0xF7; /* DIV   */
    code_at[1] = 0xF1; /* r/m = ECX */
    code_at[2] = 0xC3; /* RET      */

    /* AHORA sí: la primera página pasa a R|X. La segunda sigue en PROT_NONE. */
    if (mprotect(page, (size_t)ps, PROT_READ | PROT_EXEC) != 0) {
        fprintf(stderr, "mprotect falló\n");
        return 1;
    }

    fprintf(stderr, "DIV en %p (a %ld bytes del final de su página)\n",
            (void *)code_at, (long)(page + ps - code_at));

    /* ECX = 0 -> SIGFPE. El `call` empuja la dirección de vuelta y salta. */
    __asm__ volatile("xor %%ecx, %%ecx" ::: "rcx");
    __asm__ volatile("call *%0" ::"r"(code_at)
                     : "rax", "rcx", "rdx", "memory");

    printf("curado:division por cero al borde de pagina superada\n");
    return 0;
}