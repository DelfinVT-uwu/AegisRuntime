/* aegis_maps.h — API para consulta segura del espacio de direcciones
 *
 * [SAFETY] Todas estas funciones son async-signal-safe (o lo bastante). */
#ifndef AEGIS_MAPS_H
#define AEGIS_MAPS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Inicializa el caché de /proc/self/maps. Llamar al arranque. */
void aegis_maps_init(void);

/* ¿Es legible la dirección `addr` (tiene permiso de lectura)? */
int aegis_addr_readable(uintptr_t addr);

/* ¿Es ESCRIBIBLE la dirección `addr` (tiene permiso de escritura)?
 *
 * [WHY] Existe separada de la lectura porque es la comprobación que hace
 * segura la escritura de memoria de la fase 2 (`mem_patch` en frame_out).
 * Escribir sin preguntar antes produce corrupción silenciosa: el proceso
 * escribe donde no debe, no se queja, y el síntoma aparece mucho después y
 * en otro sitio. Antes de escribir el divisor corregido hay que SABER que la
 * página lo admite. */
int aegis_addr_writable(uintptr_t addr);

/* Copia hasta `want` bytes legibles desde `rip` a `out`, PARÁNDOSE en el
 * primer byte no legible. Devuelve cuántos copió (puede ser 0, o menos que
 * `want` si la instrucción está al final de una página). NUNCA provoca un
 * SIGSEGV: esa es toda la razón de existir. */
int aegis_read_code_prefix(uintptr_t rip, unsigned char *out, size_t want);

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_MAPS_H */