/* =============================================================================
 * capdisasm.c — Wrapper minimalista de Capstone para AegisRuntime
 * =============================================================================
 *
 * [POR QUÉ CAPSTONE]
 * El decodificador artesanal (`fastpath.rs`) está correcto para los casos Fase 1
 * (DIV/IDIV, MOV a memoria, JCC) y sirve para la demostración. Pero para
 * "hacerlo de lo mejor" necesitamos:
 *   - Decodificación exacta: VEX/EVEX, SIB, prefixes, modos 16/32/64, REX.W.
 *   - Mantenimiento y corrección probadas (miles de tests en la wild).
 *   - Menos riesgo de false positives al tomar decisiones de curación.
 *
 * Capstone 5.0.9 está disponible. Se usa solo para DECODIFICAR, no para ejecutar.
 * Todo lo de mitigación sigue en Rust (engine). El wrapper es C, llamado desde
 * Rust por FFI, con allocations cero en el path caliente.
 *
 * [REGLA DE SEGURIDAD]
 * Se decodifica SOBRE bytes copiados de forma segura (frame_in.code/code_len),
 * nunca directamente desde RIP de memoria del proceso. Esto nos evita el bug
 * que acabamos de corregir (doble fallo dentro del handler).
 * ========================================================================== */

#include <capstone/capstone.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>

#include "aegis_capdisasm.h"

/* ---------------------------------------------------------------------------
 * [API] CAPSTONE SE CARGA PEREZOSAMENTE (dlopen), NO COMO DEPENDENCIA DE ENLACE
 *
 * [POR QUÉ] Medido en este host: enlazar `-lcapstone` costs ~1.4 ms de
 * ARRANQUE en CADA proceso preloadeado, porque ld.so tiene que resolver y
 * mapear libcapstone.so.5 (7.4 MB) antes de llamar a main(). Y lauahora
 * mismo ese coste es por NADA: `aegis_capstone_init()` no lo llama nadie, así
 * que la biblioteca se mapea entera, resuelve sus relocaciones y se queda sin
 * usar en la memoria de cada proceso que se cura.
 *
 * Un runtime cuyo propósito es "no harmed al proceso" no puede permitirse pagar
 * 1.4 ms y 7.4 MB de mapped por un componente que nadie invoca. Con dlopen la
 * biblioteca se carga la PRIMERA VEZ que se use de verdad —o nunca—.
 *
 * [NOTE] Esto NO cambia la corrección: las cabeceras de Capstone siguen
 * compilándose (hacen falta para los layouts de cs_insn/cs_x86/cs_x86_op y
 * para las constantes X86_REG_*), pero los símbolos se resuelven en runtime.
 * Los layouts son parte de la ABI pública y estable dentro de la v5.
 * ------------------------------------------------------------------------ */

/* Punteros a función, resueltos en el primer aegis_capstone_init().
 * Las firmas son las EXACTAS de capstone.h en la v5 (nota: `cs_option` NO es
 * variádica en la v5, es `(csh, cs_opt_type, size_t)`), para que el compilador
 * pueda comprobar que el puntero y el símbolo coinciden. */
static cs_err    (*p_cs_open)(cs_arch, cs_mode, csh *)          = NULL;
static cs_err    (*p_cs_option)(csh, cs_opt_type, size_t)       = NULL;
static size_t    (*p_cs_disasm)(csh, const uint8_t *, size_t,
                                uint64_t, size_t, cs_insn **)   = NULL;
static void      (*p_cs_free)(cs_insn *, size_t)                 = NULL;
static cs_err    (*p_cs_close)(csh *)                            = NULL;

static csh g_handle = 0;

int aegis_capstone_init(void)
{
    if (g_handle)
        return 0; /* idempotente */

    void *h = dlopen("libcapstone.so.5", RTLD_LAZY | RTLD_LOCAL);
    if (h == NULL)
        h = dlopen("libcapstone.so.4", RTLD_LAZY | RTLD_LOCAL);
    if (h == NULL)
        return -1;

    /* [WARN] Los casts de `void*` a puntero-a-función son UB en ISO C. POSIX
     * los garantiza para dlsym(); aquí además se usa el union de §"Resolución
     * del núcleo Rust" de trap_handler.c, que es la forma con respaldo
     * normativo. */
    union { void *obj; cs_err (*fn)(cs_arch, cs_mode, csh *); }  u_open;
    union { void *obj; cs_err (*fn)(csh, cs_opt_type, size_t); } u_opt;
    union { void *obj; size_t (*fn)(csh, const uint8_t *, size_t,
                                    uint64_t, size_t, cs_insn **); } u_dis;
    union { void *obj; void  (*fn)(cs_insn *, size_t); }        u_free;
    union { void *obj; cs_err (*fn)(csh *); }                    u_close;

    u_open.obj  = dlsym(h, "cs_open");
    u_opt.obj   = dlsym(h, "cs_option");
    u_dis.obj   = dlsym(h, "cs_disasm");
    u_free.obj  = dlsym(h, "cs_free");
    u_close.obj = dlsym(h, "cs_close");
    if (!u_open.obj || !u_opt.obj || !u_dis.obj || !u_free.obj || !u_close.obj)
        return -1;

    p_cs_open   = u_open.fn;
    p_cs_option = u_opt.fn;
    p_cs_disasm = u_dis.fn;
    p_cs_free   = u_free.fn;
    p_cs_close  = u_close.fn;

    /* x86_64: modo de 64 bits. */
    if (p_cs_open(CS_ARCH_X86, CS_MODE_64, &g_handle) != CS_ERR_OK)
        return -1;

    /* Optimizaciones seguras: solo detalles que no cambian el significado. */
    p_cs_option(g_handle, CS_OPT_DETAIL, CS_OPT_ON);
    p_cs_option(g_handle, CS_OPT_SKIPDATA, CS_OPT_OFF);

    return 0;
}

void aegis_capstone_close(void)
{
    if (g_handle && p_cs_close) {
        p_cs_close(&g_handle);
        g_handle = 0;
    }
}

int aegis_cap_disasm(const unsigned char *code, size_t code_len,
                     uint64_t addr, aegis_insn_t *out, size_t max_out)
{
    if (g_handle == 0 || out == NULL || max_out == 0)
        return -1;

    cs_insn *insn = NULL;
    size_t count = p_cs_disasm(g_handle, code, code_len, addr, 1, &insn);

    if (count == 0 || insn == NULL) {
        /* Decodificación fallida: instrucción inválida/truncada. */
        p_cs_free(insn, count);
        return 0;
    }

    /* Copiamos SOLO lo que necesitamos al struct plano (no pasa structs de
     * Capstone por ABI). */
    const cs_insn *i = insn;
    const cs_x86 *xi = &(i->detail->x86);

    memset(out, 0, sizeof(*out));
    out->id = i->id;
    out->len = (uint8_t)i->size;
    out->address = i->address;

    /* [BUG] `xi->modrm != 0` como "tiene ModRM" es FALSO: el byte ModRM puede
     * valer 0x00 legítimamente (`div [rax+0]`, mod=00 reg=000 rm=000), y esa
     * comprobación lo declararía "sin ModRM". El predicado correcto es el
     * modo de direccionamiento que Capstone ya calculó: hay ModRM si y solo
     * si hay al menos un operando de memoria, o si el opcode lo exige. Se usa
     * `op_count > 0` como proxy conservative: si hay operandos, Capstone ya
     * resolvió el ModRM por nosotros y no vamos a reinterpretar sus bytes. */
    out->has_modrm = (uint8_t)(xi->op_count > 0 ? 1 : 0);
    out->modrm = (uint8_t)xi->modrm;
    out->opcode[0] = i->bytes[0];
    if (i->size >= 2)
        out->opcode[1] = i->bytes[1];
    else
        out->opcode[1] = 0;

    /* Extensión REX (para distinguir SPL/BPL/SIL/DIL vs AH/CH/DH/BH) */
    out->rex = xi->rex;
    out->displacement = xi->disp;
    /* [NOTE] NO se copian `scale` ni `op_size`: en Capstone 5 viven en
     * `cs_x86_op` (`op.mem.scale`), no en `cs_x86`. Un wrapper que los leyera
     * de `xi` no compilaría, que es la forma más barata de no tener un
     * campo mentiroso en el struct. El ancho del divisor y la escala los
     * deduce `aegis_core::fastpath` de los bytes (F6=8 bits, prefijo 66=16),
     * que es donde se necesitan y donde ya se testea. */

    /* Registros implicados (para sacar divisor/dividendo con seguridad) */
    out->reg_cnt = (uint8_t)xi->op_count;
    for (int op = 0; op < AEGIS_CAP_MAX_OPS; op++) {
        if (op >= (int)xi->op_count) {
            out->operands[op].type = X86_OP_INVALID;
            out->operands[op].reg = X86_REG_INVALID;
            out->operands[op].mem_base = X86_REG_INVALID;
            out->operands[op].mem_index = X86_REG_INVALID;
            out->operands[op].scale = 1;
            out->operands[op].mem_disp = 0;
            continue;
        }
        const cs_x86_op *o = &xi->operands[op];
        out->operands[op].type = o->type;
        out->operands[op].scale = 1;
        if (o->type == X86_OP_REG) {
            out->operands[op].reg = o->reg;
            out->operands[op].mem_base = X86_REG_INVALID;
            out->operands[op].mem_index = X86_REG_INVALID;
            out->operands[op].mem_disp = 0;
        } else if (o->type == X86_OP_MEM) {
            out->operands[op].reg = X86_REG_INVALID;
            out->operands[op].mem_base = o->mem.base;
            out->operands[op].mem_index = o->mem.index;
            out->operands[op].scale = o->mem.scale;
            out->operands[op].mem_disp = o->mem.disp;
        } else {
            out->operands[op].reg = X86_REG_INVALID;
            out->operands[op].mem_base = X86_REG_INVALID;
            out->operands[op].mem_index = X86_REG_INVALID;
            out->operands[op].scale = 1;
            out->operands[op].mem_disp = 0;
        }
    }

    p_cs_free(insn, count);
    return 1; /* decodificado con éxito */
}