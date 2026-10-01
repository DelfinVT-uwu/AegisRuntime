/*
 * idiv_overflow.c — Demo: SIGFPE por DESBORDAMIENTO, no por divisor cero.
 *
 * [POR QUÉ EXISTE]
 * Refuta una afirmación que el motor daba por cierta. `decide_fpe` justificaba
 * su cura con: "1 divide a cualquier cosa y el cociente nunca desborda". Es
 * FALSO, y al revés: dividir un dividendo que no cabe entre 1 produce un
 * cociente que tampoco cabe, así que forzar el divisor a 1 hace el
 * desbordamiento INEVITABLE.
 *
 * Con el código anterior el motor entraba en bucle, repetía la cura y moría
 * por el antibucles (regla 5) sin resolver nada.
 *
 * [LO QUE OCURRE AHORA]
 * Los dos casos se distinguen mirando el VALOR REAL DEL DIVISOR en los
 * registros, no por `si_code`: medido en esta máquina, Linux x86 reporta
 * siempre `FPE_INTDIV` para cualquier `#DE` de división, así que `si_code`
 * no distingue nada.
 *
 *   - divisor == 0 (RCX=0)      -> se pone el divisor a 1        (regla 1)
 *   - divisor != 0 (RCX=7)      -> el #DE es overflow: se pone el
 *                                   DIVIDENDO RDX:RAX a cero     (regla 4)
 *
 * Se prueba la secuencia completa: primero divisor cero, después overflow.
 * Ambos deben quedar curarados y el proceso debe salir con 0.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void)
{
    long ps = sysconf(_SC_PAGESIZE);
    /* DOS páginas: la segunda es guard page, como en page_edge.c. El DIV va
     * al final de la primera seguido de un RET, para que el camino curado
     * pueda terminar en vez de caer sobre la hoja de trampolín. */
    unsigned char *p = mmap(NULL, (size_t)(ps * 2), PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED)
        return 1;
    if (mprotect(p + ps, (size_t)ps, PROT_NONE) != 0)
        return 1;

    unsigned char *code_at = p + ps - 3;
    code_at[0] = 0xF7; /* DIV   */
    code_at[1] = 0xF1; /* r/m = ECX */
    code_at[2] = 0xC3; /* RET      */
    if (mprotect(p, (size_t)ps, PROT_READ | PROT_EXEC) != 0)
        return 1;

    /* --- Caso A: DIVISOR CERO ---------------------------------------- */
    fprintf(stderr, "caso A: RCX=0 (divisor cero)\n");
    __asm__ volatile("mov $0x100, %%rax" ::: "rax");
    __asm__ volatile("xor %%edx, %%edx" ::: "rdx");
    __asm__ volatile("xor %%ecx, %%ecx" ::: "rcx");
    __asm__ volatile("call *%0" ::"r"(code_at)
                     : "rax", "rcx", "rdx", "memory");

    /* --- Caso B: DESBORDAMIENTO --------------------------------------- */
    /* RAX=0x100, RDX=0xdeadbeef, RCX=7. El dividendo es de 128 bits y al
     * dividirlo entre 7 el cociente no cabe en 64 bits -> #DE de overflow. */
    fprintf(stderr, "caso B: RDX=0xdeadbeef, RCX=7 (overflow del cociente)\n");
    __asm__ volatile("mov $0x100, %%rax" ::: "rax");
    __asm__ volatile("mov $0xdeadbeef, %%rdx" ::: "rdx");
    __asm__ volatile("mov $7, %%ecx" ::: "rcx");
    __asm__ volatile("call *%0" ::"r"(code_at)
                     : "rax", "rcx", "rdx", "memory");

    printf("curado:divisor cero y overflow de cociente superados\n");
    return 0;
}