#ifndef AEGIS_CAPDISASM_H
#define AEGIS_CAPDISASM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Wrapper plano para Capstone (x86_64). */

#define AEGIS_CAP_MAX_OPS 4

typedef struct aegis_insn_op {
    int      type;        /* X86_OP_* */
    int      reg;         /* X86_REG_* */
    int      mem_base;    /* X86_REG_* o X86_REG_INVALID */
    int      mem_index;   /* X86_REG_* o X86_REG_INVALID */
    int64_t  mem_disp;
    int      scale;       /* 1/2/4/8 (indexado) */
} aegis_insn_op_t;

typedef struct aegis_insn {
    uint32_t        id;        /* CS_x86_insn */
    uint8_t         len;
    uint64_t        address;
    uint8_t         has_modrm;
    uint8_t         modrm;
    uint8_t         opcode[2];
    uint8_t         rex;
    int64_t         displacement;
    /* [NOTE] Sin `scale`/`op_size`: en Capstone 5 son `cs_x86_op.mem.scale` y
     * el tamaño se deduce del prefijo de operand-size, no hay campo global. La
     * escala de un operando está en `operands[n].scale`. */
    uint8_t         reg_cnt;
    aegis_insn_op_t operands[AEGIS_CAP_MAX_OPS];
} aegis_insn_t;

/* Inicializa el motor de Capstone. Devuelve 0 si OK, -1 si error.
 * Idempotente. */
int aegis_capstone_init(void);

/* Cierra Capstone. */
void aegis_capstone_close(void);

/* Decodifica una instrucción desde `code[0..code_len-1]`, dirección virtual
 * `addr`. Si tiene éxito devuelve 1 y rellena `out`. Si no reconoce, devuelve
 * 0. Si error de estado (no inicializado, parámetros inválidos) devuelve -1. */
int aegis_cap_disasm(const unsigned char *code, size_t code_len,
                     uint64_t addr, aegis_insn_t *out, size_t max_out);

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_CAPDISASM_H */