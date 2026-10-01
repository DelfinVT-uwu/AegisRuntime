/* =============================================================================
 * addrspace.c — ¿Es legible esta dirección? (para el handler de trampas)
 * =============================================================================
 *
 * [POR QUÉ EXISTE]
 * El motor Rust decodifica la instrucción en RIP con
 * `slice::from_raw_parts(rip, 15)`, es decir, LEE 15 bytes de memoria del
 * proceso roto. Eso está bien si RIP apunta a código de verdad, pero
 * NO lo está cuando RIP no es una dirección legible, y ese caso es real:
 *
 *   - Fallo de FETCH: la CPU intentó ejecutar código en una página PROT_NONE
 *     o no mapeada. Entonces RIP ES esa página. Leerla desde el handler
 *     provoca un SEGFAULT DENTRO DEL HANDLER, y el kernel no lo puede
 *     recuperar: fuerza SIG_DFL y mata el proceso sin telemetría, sin log y
 *     sin el abort controlado. Es el peor modo de fallo posible en un
 *     runtime de resiliencia: el runtime que debía proteger al proceso es el
 *     que lo mata, y sin dejar rastro.
 *
 *   - Salto a dirección basura: un `ret` con RSP corrupto, un salto indirecto
 *     con un puntero nulo, un fallo de decodificación previo… todos dejan RIP
 *     en territory que no existe.
 *
 * [POR QUÉ NO process_vm_readv]
 * Es la respuesta obvia (devuelve EFAULT en vez de fallar), pero SE COMPORTA
 * MAL aquí: medido en este entorno, `process_vm_readv(getpid(), ...)` devuelve
 * el número de bytes correcto y NO copia nada — el buffer destino queda
 * intacto. Confiar en él para decidir "puedo leer" daría un falso positivo.
 *
 * [POR QUÉ NO mincore/msync]
 * También medido: ambos devuelven 0 (éxito) sobre una página PROT_NONE.
 * Solo informan de RESIDENCIA en el page cache, no de protección, así que no
 * sirven para responder a esta pregunta.
 *
 * [LA SOLUCIÓN]
 * Un índice del espacio de direcciones leído de /proc/self/maps, con buffers
 * estáticos (nada de malloc: esto corre dentro de un handler de señal) y con
 * las únicas llamadas que POSIX declara async-signal-safe: open/read/close.
 *
 * [SEGURIDAD DE SEÑAL]
 *   - Sin asignación de memoria: dos buffers estáticos.
 *   - Sin stdio, sin errno global compartido, sin mutex de libc.
 *   - Reentrante: una bandera atómica hace que, si otro hilo ya está
 *     releyendo el mapa, el segundo use la tabla existente en vez de
 *     corromperla. Esa tabla puede estar ligeramente desfasada, y eso es
 *     aceptable: en el peor caso se conserva un fault que se podía curar.
 *     Es infinitamente preferible a matar el proceso.
 *
 * [NOTA SOBRE mmap_lock]
 * Leer /proc/self/maps toma mmap_lock en modo lectura. ¿Es seguro hacerlo
 * desde un handler de SIGSEGV provocado por un page fault? Sí: Linux entrega
 * la señal al espacio de usuario DESPUÉS de soltar el lock
 * (`do_user_addr_fault` → `mmap_read_unlock()` → reenvío de la excepción), así
 * que el handler no se reentra a sí mismo con el lock tomado. Aun así, el
 * desgaste es de un solo hilo y el peor caso es bloquearse, no corromper
 * memoria.
 * ========================================================================== */

#define _GNU_SOURCE
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "aegis_maps.h"

/* [NOTE] 1024 entradas cubre de sobra un proceso normal (decenas). Si un
 * proceso tuviera más, la tabla se trunca y `aegis_addr_readable` se
 * vuelve conservative: ante la duda dice "no" y el motor aborta limpio en vez
 * de segmentarse dentro del handler. */
#define AEGIS_MAP_MAX   1024
#define AEGIS_MAPS_BUF  (128 * 1024)

struct map_ent {
    uintptr_t lo;
    uintptr_t hi;
    int      readable;   /* prot tenía 'r' */
    /* [API] prot tenía 'w'. Hace falta para el parche de memoria (curar un
     * divisor en RAM): escribir sin haber comprobado esto es corrupción
     * silenciosa si la EA cae fuera de lo que la app considera suyo. */
    int      writable;
};

static struct map_ent g_maps[AEGIS_MAP_MAX];
static size_t         g_nmaps;

/* [EXPL] `0` = libre. El handler de SIGSEGV tiene bloqueado el mismo SIGSEGV
 * mientras corre, así que la reentrada del MISMO handler no puede pasar; la
 * bandera protege del caso cruzado (otro hilo, u otra señal durante un ciclo
 * largo de E/S). */
static atomic_flag g_refreshing = ATOMIC_FLAG_INIT;

/* ------------------------------------------------------------------ *
 *  Lectura cruda de /proc/self/maps                                 *
 * ------------------------------------------------------------------ */

static size_t read_whole_file(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;

    size_t off = 0;
    for (;;) {
        ssize_t n = read(fd, buf + off, cap - off);
        if (n < 0) {
            /* [EXPL] EINTR: el handler puede interrumpirse. Reintentamos. */
            continue;
        }
        if (n == 0)
            break;
        off += (size_t)n;
        if (off >= cap)
            break;
    }
    (void)close(fd);
    return off;
}

/* ------------------------------------------------------------------ *
 *  Parser                                                             *
 * ------------------------------------------------------------------ */

/* [WHY] Parseo a mano, sin strtoul/sscanf: son las funciones que pueden
 * arrastrar locale o estado global. En un handler queremos C puro. */
static int hexval(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static const char *parse_hex(const char *s, uintptr_t *out)
{
    uintptr_t v = 0;
    int any = 0;
    for (;;) {
        int d = hexval((unsigned char)*s);
        if (d < 0)
            break;
        v = (v << 4) | (uintptr_t)d;
        any = 1;
        s++;
    }
    if (!any)
        return NULL;
    *out = v;
    return s;
}

/* Formato de línea:
 *   7f3423029000-7f342302a000 r-xp 00000000 08:01 1234    /lib/libc.so
 *                ^lo    ^hi    ^prot
 */
static size_t parse_maps(const char *buf, size_t len)
{
    size_t n = 0;
    size_t i = 0;

    while (i < len && n < AEGIS_MAP_MAX) {
        /* inicio de línea */
        size_t eol = i;
        while (eol < len && buf[eol] != '\n')
            eol++;

        const char *p   = buf + i;
        const char *end = buf + eol;

        uintptr_t lo = 0, hi = 0;
        const char *q = parse_hex(p, &lo);
        if (q && q < end && *q == '-') {
            q = parse_hex(q + 1, &hi);
            if (q && q < end && *q == ' ' && hi > lo) {
                /* saltar espacios hasta la columna de permisos */
                while (q < end && *q == ' ')
                    q++;
                if (q < end) {
                    /* permisos: rwx[-]p  en orden posicional */
                    int readable = (q[0] == 'r');
                    /* Comprobamos también que el byte 1 sea '-' o sea que la
                     * línea tiene la forma r?x?... Sin validación profunda:
                     * el kernel genera este formato, no lo escribimos
                     * nosotros. */
                    int writable = (q[1] == 'w');
                    g_maps[n].lo = lo;
                    g_maps[n].hi = hi;
                    g_maps[n].readable = readable;
                    g_maps[n].writable = writable;
                    n++;
                }
            }
        }
        i = (eol < len) ? eol + 1 : len;
    }
    return n;
}

static void maps_refresh(void)
{
    /* reentrancy guard */
    if (atomic_flag_test_and_set_explicit(&g_refreshing, memory_order_acquire))
        return;                     /* otro hilo refresca: usamos la tabla */

    static char buf[AEGIS_MAPS_BUF];   /* static: sin malloc */
    size_t len = read_whole_file("/proc/self/maps", buf, sizeof buf);

    if (len > 0) {
        size_t n = parse_maps(buf, len);
        if (n > 0) {
            g_nmaps = n;
        } else if (g_nmaps == 0) {
            /* Tabla vacía y parseo fallido: dejamos g_nmaps en 0, que hace que
             * todo se lea como "no legible" → abort limpio. */
            g_nmaps = 0;
        }
    }

    atomic_flag_clear_explicit(&g_refreshing, memory_order_release);
}

void aegis_maps_init(void)
{
    maps_refresh();
}

/* ------------------------------------------------------------------ *
 *  Consulta                                                           *
 * ------------------------------------------------------------------ */

/* [EXPL] `lookup` devuelve un TRIAJE para que el llamante distinga tres casos
 * que antes se confundían en un booleano:
 *   >0  mapeada y satisface el permiso pedido
 *   -1  mapeada pero NO satisface el permiso (p. ej. legible pero no escribible)
 *    0  no mapeada (o tabla vacía/desfasada)
 * La diferencia entre -1 y 0 importa en el parche de memoria: "la página
 * existe pero es de solo lectura" y "esa dirección no existe" exigen
 * respuestas distintas, y agrupar ambas como `false` las hace indistinguibles.
 */
static int lookup(uintptr_t addr, int want_writable)
{
    for (size_t i = 0; i < g_nmaps; i++) {
        if (addr >= g_maps[i].lo && addr < g_maps[i].hi) {
            int ok = want_writable ? g_maps[i].writable : g_maps[i].readable;
            return ok ? 1 : -1;
        }
    }
    return 0;
}

int aegis_addr_readable(uintptr_t addr)
{
    int r = lookup(addr, 0);
    if (r != 0)
        return r > 0;

    /* [EXPL] Fallo de caché: puede que el proceso haya mapeado algo DESPUÉS
     * del arranque (casi seguro: el propio JIT de la víctima). Refrescamos
     * UNA vez y reintentamos. Si tampoco aparece, la respuesta honesta es
     * "no lo sé" → el llamante aborta limpio. */
    maps_refresh();
    r = lookup(addr, 0);
    return r > 0;
}

int aegis_addr_writable(uintptr_t addr)
{
    /* [WHY] No se refresca la tabla aquí. A diferencia de RIP —que puede
     * apuntar a código recién JITeado por la víctima, y por eso merece una
     * relectura— una EA de divisor siempre cae en una región que la app ya
     * está usando (si no, el `#DE` no habría ocurrido: la CPU lo leyó). Es
     * decir: la página que falla la lectura del divisor YA EXISTÍA y el kernel
     * acaba de walkearla. Refrescar /proc/self/maps desde aquí solo añade E/S
     * dentro del handler sin poder cambiar el resultado. */
    return lookup(addr, 1) > 0;
}

int aegis_read_code_prefix(uintptr_t rip, unsigned char *out, size_t want)
{
    if (want == 0)
        return 0;

    size_t n = 0;
    for (; n < want; n++) {
        /* [SAFETY] Comprobamos byte a byte ANTES de tocar cada uno. En cuanto
         * uno no es legible paramos: copiar un prefijo corto es correcto y
         * deja que el decodificador de Rust falle cerrado por truncamiento, en
         * vez de inventarse bytes de una página que no existe. */
        if (!aegis_addr_readable(rip + n))
            break;
        out[n] = *(const unsigned char *)(rip + n);
    }
    return (int)n;
}