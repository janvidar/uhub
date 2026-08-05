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

#ifndef HAVE_UHUB_HBRI_H
#define HAVE_UHUB_HBRI_H

#include "adc/adctypes.h"

/*
 * HBRI ("hybrid connectivity") is an unofficial ADC extension (originally from
 * AirDC++) that lets a dual-stack client prove it is reachable over both IPv4
 * and IPv6. After a client logs in over one protocol, the hub asks it to open a
 * short-lived secondary connection over the OTHER protocol. On success the
 * client's INF carries both an I4 and an I6 address so peers behind either
 * protocol can connect to it.
 *
 * See doc/architecture.txt and the reference implementation maksis/adchpp-hbri.
 */

struct hub_info;
struct hub_user;
struct adc_message;

/**
 * @return 1 if HBRI is enabled and the hub knows both an IPv4 and an IPv6
 * address to advertise, 0 otherwise.
 */
extern int hbri_is_enabled(struct hub_info* hub);

/**
 * @return 1 if the user is a candidate for HBRI secondary-protocol validation:
 * HBRI is enabled, the user supports the HBRI feature, and its login INF
 * signalled connectivity over the protocol family it did NOT connect over.
 */
extern int hbri_is_candidate(struct hub_info* hub, struct hub_user* user);

/**
 * Send the secondary-protocol validation request (ITCP) to the user. The user
 * is NOT held: it logs in (or stays logged in) over its primary protocol, and
 * the secondary address is added later via an INF update if and when the
 * validation connection succeeds. There is therefore no timeout to manage.
 */
extern void hbri_send_validation_request(struct hub_info* hub, struct hub_user* user);

/**
 * Called from on_login_success() just before the user's INF is broadcast. If
 * the user is an HBRI candidate the unverified second-family address is stripped
 * (so the initial broadcast is primary-only) and a validation request is sent.
 */
extern void hbri_on_login(struct hub_info* hub, struct hub_user* user);

/**
 * Handle an HTCP validation reply received on a fresh (validation) connection.
 * On success the address observed on that connection is merged into the
 * referenced user's INF and broadcast as an update. The validation connection
 * is always closed afterwards (returns -1).
 */
extern int hbri_handle_validation(struct hub_info* hub, struct hub_user* vuser, struct adc_message* cmd);

/*
 * Stateless token primitives (exposed for testing). A token is the user's SID
 * prefix followed by a Tiger MAC over the per-hub secret, the SID and the
 * connection timestamp.
 */
#define HBRI_SID_LEN 4
#define HBRI_TOKEN_LEN (HBRI_SID_LEN + MAX_CID_LEN)

extern void hbri_token_make(struct hub_info* hub, struct hub_user* user, char* out /* >= HBRI_TOKEN_LEN+1 */);
extern int hbri_token_check(struct hub_info* hub, struct hub_user* user, const char* token);

/**
 * @return 1 if the string is a plausible ADC port: decimal digits only, at most
 * MAX_PORT_LEN of them, and in the range 1-65535.
 */
extern int hbri_port_is_valid(const char* port);

/**
 * Remember the UDP port the client advertised for protocol family 'af', so it
 * can be merged back into the INF once that family's address is validated. The
 * matching U4/U6 field is stripped from the broadcast INF by the caller, since
 * the address it belongs to is unproven until then.
 *
 * Does nothing if 'cmd' carries no U-flag for that family (on an INF update an
 * absent field means "unchanged"); an invalid value clears the stored port.
 */
extern void hbri_remember_udp_port(struct hub_user* user, struct adc_message* cmd, int af);

#endif /* HAVE_UHUB_HBRI_H */
