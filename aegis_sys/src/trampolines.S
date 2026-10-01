# -----------------------------------------------------------------------------
# trampolines.S — Stubs JIT en ensamblador puro (x86-64, AT&T/GAS).
#
# Responsabilidad: el "brazo robótico" que Fase 2 escribirá en la JIT Code
# Cave: secuencias cortas que ejecutan la curación y devuelven el flujo a la
# instrucción siguiente del programa. Fase 1 no las emite todavía; este
# archivo fija el PATRÓN de bytes y la disciplina de preservación de
# registros que el generador de parches (Fase 2) debe respetar.
#
# [WARN] Ningún compilador (ni siquiera `naked` de C) garantiza aquí lo que
# garantiza el ensamblador a mano: que NO se toque ni un registro de más.
# Por eso el cuerpo de curación se declara en C (aegis_cure_*), pero el
# prólogo/epílogo que salva EFLAGS+GPRs es asm puro.
# -----------------------------------------------------------------------------

# [EXPL] pushfq/popfq salvan el EFLAGS *completo* (ZF/CF/OF...). Un handler C
# normal podría trastear con banderas sin que el compilador lo note; aquí la
# instrucción original se re-ejecuta o se salta, y sus banderas deben ser las
# que el programa espera. Por eso el par de pushfq/popfq es obligatorio en
# TODA entrada a la code cave.

.text
.globl aegis_trampoline_template
.globl aegis_trampoline_template_end

# -----------------------------------------------------------------------------
# aegis_trampoline_template — patrón canónico de parche.
#
# Ejemplo concreto (el motivo real de existir):
#   original:  DIV ECX        ; bytes F7 F1 — falla si ECX == 0
#   parche:    este stub      ; fuerza RCX = 1 y re-ejecuta DIV ECX
#
# [TODO(fase2)] el generador emitirá este molde copiando el bloque entre
# template y template_end, y rellenando cure_fn y resume_ip con rel32.
# -----------------------------------------------------------------------------
.type aegis_trampoline_template, @function
aegis_trampoline_template:
    pushfq                      # 1. EFLAGS a la pila (ver nota arriba)
    push   %rax                 # 2. preservar RAX del programa roto

    # [NOTE] El cuerpo de curación NO puede usar la pila normal del
    # programa: viene de un crash y su estado es sospechoso. Por eso la
    # code cave usa la alt-stack del motor (SS:SP ya apuntan ahí cuando el
    # kernel invoca el handler; el stub solo debe mantener ese contrato).
    call   aegis_cure_fn        # 3. puntero rellenado por el generador JIT:
                                #    escribe registros de curación en el hilo

    pop    %rax                 # 4. restaurar RAX
    popfq                       # 5. restaurar EFLAGS

    jmp    *aegis_resume_ip(%rip)  # 6. salto a original_ip + longitud; el
                                #    flujo del programa continúa sin saber
                                #    que algo se curó en medio
aegis_cure_fn:
    .quad   0                   # slot rellenado con la dirección del helper C
aegis_resume_ip:
    .quad   0                   # slot rellenado con RIP + instruction_length

aegis_trampoline_template_end:
    nop                         # marcador de fin (el generador mide el molde)
.size aegis_trampoline_template, .-aegis_trampoline_template