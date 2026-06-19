/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2026, Jan Vidar Krey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

/*
 * Small ADC value types and protocol identifier limits shared between the hub
 * core (adc/adcconst.h) and the plugin ABI (plugin_api/types.h). This is the
 * single source of truth for these definitions: include this header instead of
 * redefining sid_t or the MAX_*_LEN limits (which used to be duplicated behind
 * the SID_T_DEFINED / #ifndef guards).
 */

#ifndef HAVE_UHUB_ADC_TYPES_H
#define HAVE_UHUB_ADC_TYPES_H

#include <stdint.h>

/* ADC session ID. */
typedef uint32_t sid_t;

/* Maximum lengths of ADC protocol identifiers, in bytes (excluding any NUL
 * terminator). */
#define MAX_CID_LEN  39
#define MAX_NICK_LEN 64
#define MAX_PASS_LEN 64
#define MAX_UA_LEN   32

/* Size of a Tiger hash digest, in bytes. */
#define TIGERSIZE    24

#endif /* HAVE_UHUB_ADC_TYPES_H */
