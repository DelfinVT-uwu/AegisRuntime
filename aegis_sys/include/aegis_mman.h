#ifndef AEGIS_MMAN_H
#define AEGIS_MMAN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Shadow zero-page: dirección donde redirigir accesos a NULL (Fase 2). */
extern uint8_t *g_shadow_page;

/* Obtiene base+size de la shadow page para posibles futuras API. */
size_t aegis_mman_shadow_size(void);
uint8_t *aegis_mman_shadow_base(void);

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_MMAN_H */