/*
 * uhub - A tiny ADC p2p connection hub
 * Copyright (C) 2007-2010, Jan Vidar Krey
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "uhub.h"

struct hub_info* g_hub = 0;

int hub_handle_message(struct hub_info* hub, struct hub_user* u, const char* line, size_t length)
{
	int ret = 0;
	struct adc_message* cmd = 0;
	
	LOG_PROTO("recv %s: %s", sid_to_string(u->id.sid), line);
	
	if (user_is_disconnecting(u))
		return -1;

	cmd = adc_msg_parse_verify(u, line, length);
	if (cmd)
	{
		switch (cmd->cmd)
		{
			case ADC_CMD_HSUP: ret = hub_handle_support(hub, u, cmd); break;
			case ADC_CMD_HPAS: ret = hub_handle_password(hub, u, cmd); break;
			case ADC_CMD_BINF: ret = hub_handle_info(hub, u, cmd); break;
			case ADC_CMD_DINF:
			case ADC_CMD_EINF:
			case ADC_CMD_FINF:
				/* these must never be allowed for security reasons,
				   so we ignore them. */
				break;

			case ADC_CMD_EMSG:
			case ADC_CMD_DMSG:
			case ADC_CMD_BMSG:
			case ADC_CMD_FMSG:
				ret = hub_handle_chat_message(hub, u, cmd);
				break;

			case ADC_CMD_BSCH:
			case ADC_CMD_DSCH:
			case ADC_CMD_ESCH:
			case ADC_CMD_FSCH:
			case ADC_CMD_DRES:
			case ADC_CMD_DRCM:
			case ADC_CMD_DCTM:
				cmd->priority = -1;
				if (hub->config->chat_only && u->credentials < cred_operator)
				{
					/* These below aren't allowed in chat only hubs */
					break;
				}
			
			default:
				if (user_is_logged_in(u))
				{
					ret = route_message(hub, u, cmd);
				}
				else
				{
					ret = -1;
				}
				break;
		}
		adc_msg_free(cmd);
	}
	else
	{
		if (!user_is_logged_in(u))
		{
			ret = -1;
		}
	}
	
	return ret;
}


int hub_handle_support(struct hub_info* hub, struct hub_user* u, struct adc_message* cmd)
{
	int ret = 0;
	int index = 0;
	int ok = 1;
	char* arg = adc_msg_get_argument(cmd, index);

	if (hub->status == hub_status_disabled && u->state == state_protocol)
	{
		on_login_failure(hub, u, status_msg_hub_disabled);
		hub_free(arg);
		return -1;
	}

	while (arg)
	{
		if (strlen(arg) == 6)
		{
			fourcc_t fourcc = FOURCC(arg[2], arg[3], arg[4], arg[5]);
			if (strncmp(arg, ADC_SUP_FLAG_ADD, 2) == 0)
			{
				user_support_add(u, fourcc);
			}
			else if (strncmp(arg, ADC_SUP_FLAG_REMOVE, 2) == 0)
			{
				user_support_remove(u, fourcc);
			}
			else
			{
				ok = 0;
			}
		}
		else
		{
			ok = 0;
		}
		
		index++;
		hub_free(arg);
		arg = adc_msg_get_argument(cmd, index);
	}

	if (u->state == state_protocol)
	{
		if (index == 0) ok = 0; /* Need to support *SOMETHING*, at least BASE */
	
		if (ok)
		{
			hub_send_handshake(hub, u);
			net_con_set_timeout(u->connection, TIMEOUT_HANDSHAKE);
		}
		else
		{
			/* disconnect user. Do not send crap during initial handshake! */
			hub_disconnect_user(hub, u, quit_logon_error);
			ret = -1;
		}
	}

	return ret;
}


int hub_handle_password(struct hub_info* hub, struct hub_user* u, struct adc_message* cmd)
{
	char* password = adc_msg_get_argument(cmd, 0);
	int ret = 0;

	if (u->state == state_verify)
	{
		if (acl_password_verify(hub->acl, u, password))
		{
			on_login_success(hub, u);
		}
		else
		{
			on_login_failure(hub, u, status_msg_auth_invalid_password);
			ret = -1;
		}
	}
	
	hub_free(password);
	return ret;
}


int hub_handle_chat_message(struct hub_info* hub, struct hub_user* u, struct adc_message* cmd)
{
	char* message = adc_msg_get_argument(cmd, 0);
	int ret = 0;
	int relay = 1;

	if (!message || !user_is_logged_in(u))
		return 0;

	if ((cmd->cache[0] == 'B') && (message[0] == '!' || message[0] == '+'))
	{
		/*
		 * A message such as "++message" is handled as "+message", by removing the first character.
		 * The first character is removed by memmoving the string one byte to the left.
		 */
		if (message[1] == message[0])
		{
			relay = 1;
			int offset = adc_msg_get_arg_offset(cmd);
			memmove(cmd->cache+offset+1, cmd->cache+offset+2, cmd->length - offset);
			cmd->length--;
		}
		else
		{
			relay = command_dipatcher(hub, u, message);
		}
	}

	if (hub->config->chat_is_privileged && !user_is_protected(u) && (cmd->cache[0] == 'B' || cmd->cache[0] == 'F'))
	{
		relay = 0;
	}

	if (relay)
	{
		/* adc_msg_remove_named_argument(cmd, "PM"); */
		if (cmd->cache[0] == 'B')
			hub_chat_history_add(hub, u, cmd);
		ret = route_message(hub, u, cmd);
	}
	hub_free(message);
	return ret;
}

void hub_chat_history_add(struct hub_info* hub, struct hub_user* user, struct adc_message* cmd)
{
	char* msg_esc   = adc_msg_get_argument(cmd, 0);
	char* message = adc_msg_unescape(msg_esc);
	char* log = hub_malloc(strlen(message) + strlen(user->id.nick) + 14);
	sprintf(log, "%s <%s> %s\n", get_timestamp(time(NULL)), user->id.nick, message);
	list_append(hub->chat_history, log);
	while (list_size(hub->chat_history) > (size_t) hub->config->max_chat_history)
	{
		char* msg = list_get_first(hub->chat_history);
		list_remove(hub->chat_history, msg);
		hub_free(msg);
	}
	hub_free(message);
	hub_free(msg_esc);
}

void hub_chat_history_clear(struct hub_info* hub)
{
	list_clear(hub->chat_history, &hub_free);
}

void hub_send_support(struct hub_info* hub, struct hub_user* u)
{
	if (user_is_connecting(u) || user_is_logged_in(u))
	{
		route_to_user(hub, u, hub->command_support);
	}
}


void hub_send_sid(struct hub_info* hub, struct hub_user* u)
{
	sid_t sid;
	struct adc_message* command;
	if (user_is_connecting(u))
	{
		command = adc_msg_construct(ADC_CMD_ISID, 10);
		sid = uman_get_free_sid(hub, u);
		adc_msg_add_argument(command, (const char*) sid_to_string(sid));
		route_to_user(hub, u, command);
		adc_msg_free(command);
	}
}


void hub_send_ping(struct hub_info* hub, struct hub_user* user)
{
	/* This will just send a newline, despite appearing to do more below. */
	struct adc_message* ping = adc_msg_construct(0, 0);
	ping->cache[0]     = '\n';
	ping->cache[1]     = 0;
	ping->length       = 1;
	ping->priority     = 1;
	route_to_user(hub, user, ping);
	adc_msg_free(ping);
}


void hub_send_hubinfo(struct hub_info* hub, struct hub_user* u)
{
	struct adc_message* info = adc_msg_copy(hub->command_info);
	int value = 0;
	
	if (user_flag_get(u, feature_ping))
	{
/*
		FIXME: These are missing:
		HH - Hub Host address ( DNS or IP )
		WS - Hub Website
		NE - Hub Network
		OW - Hub Owner name
*/
		adc_msg_add_named_argument(info, "UC", uhub_itoa(hub_get_user_count(hub)));
		adc_msg_add_named_argument(info, "MC", uhub_itoa(hub_get_max_user_count(hub)));
		adc_msg_add_named_argument(info, "SS", uhub_ulltoa(hub_get_shared_size(hub)));
		adc_msg_add_named_argument(info, "SF", uhub_itoa(hub_get_shared_files(hub)));
		
		/* Maximum/minimum share size */
		value = hub_get_max_share(hub);
		if (value) adc_msg_add_named_argument(info, "XS", uhub_itoa(value));
		value = hub_get_min_share(hub);
		if (value) adc_msg_add_named_argument(info, "MS", uhub_itoa(value));
		
		/* Maximum/minimum upload slots allowed per user */
		value = hub_get_max_slots(hub);
		if (value) adc_msg_add_named_argument(info, "XL", uhub_itoa(value));
		value = hub_get_min_slots(hub);
		if (value) adc_msg_add_named_argument(info, "ML", uhub_itoa(value));
		
		/* guest users must be on min/max hubs */
		value = hub_get_max_hubs_user(hub);
		if (value) adc_msg_add_named_argument(info, "XU", uhub_itoa(value));
		value = hub_get_min_hubs_user(hub);
		if (value) adc_msg_add_named_argument(info, "MU", uhub_itoa(value));
		
		/* registered users must be on min/max hubs */
		value = hub_get_max_hubs_reg(hub);
		if (value) adc_msg_add_named_argument(info, "XR", uhub_itoa(value));
		value = hub_get_min_hubs_reg(hub);
		if (value) adc_msg_add_named_argument(info, "MR", uhub_itoa(value));
		
		/* operators must be on min/max hubs */
		value = hub_get_max_hubs_op(hub);
		if (value) adc_msg_add_named_argument(info, "XO", uhub_itoa(value));
		value = hub_get_min_hubs_op(hub);
		if (value) adc_msg_add_named_argument(info, "MO", uhub_itoa(value));
		
		/* uptime in seconds */
		adc_msg_add_named_argument(info, "UP", uhub_itoa((int) difftime(time(0), hub->tm_started)));
	}
	
	if (user_is_connecting(u) || user_is_logged_in(u))
	{
		route_to_user(hub, u, info);
	}
	adc_msg_free(info);
	
	/* Only send banner when connecting */
	if (hub->config->show_banner && user_is_connecting(u))
	{
		route_to_user(hub, u, hub->command_banner);
	}
}

void hub_send_handshake(struct hub_info* hub, struct hub_user* u)
{
	user_flag_set(u, flag_pipeline);
	hub_send_support(hub, u);
	hub_send_sid(hub, u);
	hub_send_hubinfo(hub, u);
	route_flush_pipeline(hub, u);

	if (!user_is_disconnecting(u))
	{
		user_set_state(u, state_identify);
	}
}

void hub_send_motd(struct hub_info* hub, struct hub_user* u)
{
	if (hub->command_motd)
	{
		route_to_user(hub, u, hub->command_motd);
	}
}

void hub_send_password_challenge(struct hub_info* hub, struct hub_user* u)
{
	struct adc_message* igpa;
	igpa = adc_msg_construct(ADC_CMD_IGPA, 38);
	adc_msg_add_argument(igpa, acl_password_generate_challenge(hub->acl, u));
	user_set_state(u, state_verify);
	route_to_user(hub, u, igpa);
	adc_msg_free(igpa);
}

static void hub_event_dispatcher(void* callback_data, struct event_data* message)
{
	struct hub_info* hub = (struct hub_info*) callback_data;
	struct hub_user* user = (struct hub_user*) message->ptr;
	assert(hub != NULL);
	
	switch (message->id)
	{
		case UHUB_EVENT_USER_JOIN:
		{
			if (user_is_disconnecting(user))
				break;
		
			if (message->flags)
			{
				hub_send_password_challenge(hub, user);
			}
			else
			{
				on_login_success(hub, user);
			}
			break;
		}

		case UHUB_EVENT_USER_QUIT:
		{
			uman_remove(hub, user);
			uman_send_quit_message(hub, user);
			on_logout_user(hub, user);
			hub_schedule_destroy_user(hub, user);
			break;
		}
		
		case UHUB_EVENT_USER_DESTROY:
		{
			user_destroy(user);
			break;
		}

		case UHUB_EVENT_HUB_SHUTDOWN:
		{
			struct hub_user* u = (struct hub_user*) list_get_first(hub->users->list);
			while (u)
			{
				uman_remove(hub, u);
				user_destroy(u);
				u = (struct hub_user*) list_get_first(hub->users->list);
			}
			break;
		}


		default:
			/* FIXME: ignored */
			break;
	}
}


struct hub_info* hub_start_service(struct hub_config* config)
{
	struct hub_info* hub = 0;
	struct sockaddr_storage addr;
	socklen_t sockaddr_size;
	int server_tcp, ret, ipv6_supported, af;
	char address_buf[INET6_ADDRSTRLEN+1];
	
	hub = hub_malloc_zero(sizeof(struct hub_info));
	if (!hub)
	{
		LOG_FATAL("Unable to allocate memory for hub");
		return 0;
	}
	
	hub->tm_started = time(0);
	
	ipv6_supported = net_is_ipv6_supported();
	
	if (ipv6_supported)
		LOG_DEBUG("IPv6 supported.");
	else
		LOG_DEBUG("IPv6 not supported.");
	
	if (ip_convert_address(config->server_bind_addr, config->server_port, (struct sockaddr*) &addr, &sockaddr_size) == -1)
	{
		hub_free(hub);
		return 0;
	}
	
	af = addr.ss_family;
	if (af == AF_INET)
	{
		net_address_to_string(AF_INET, &((struct sockaddr_in*) &addr)->sin_addr, address_buf, INET6_ADDRSTRLEN);
	}
	else if (af == AF_INET6)
	{
		net_address_to_string(AF_INET6, &((struct sockaddr_in6*) &addr)->sin6_addr, address_buf, INET6_ADDRSTRLEN);
	}

	LOG_INFO("Starting " PRODUCT "/" VERSION ", listening on %s:%d...", address_buf, config->server_port);

	server_tcp = net_socket_create(af, SOCK_STREAM, IPPROTO_TCP);
	if (server_tcp == -1)
	{
		hub_free(hub);
		return 0;
	}
	
	ret = net_set_reuseaddress(server_tcp, 1);
	if (ret == -1)
	{
		hub_free(hub);
		net_close(server_tcp);
		return 0;
	}
	
	ret = net_set_nonblocking(server_tcp, 1);
	if (ret == -1)
	{
		hub_free(hub);
		net_close(server_tcp);
		return 0;
	}
	
	ret = net_bind(server_tcp, (struct sockaddr*) &addr, sockaddr_size);
	if (ret == -1)
	{
		LOG_FATAL("hub_start_service(): Unable to bind to TCP local address. errno=%d, str=%s", net_error(), net_error_string(net_error()));
		hub_free(hub);
		net_close(server_tcp);
		return 0;
	}

	ret = net_listen(server_tcp, config->server_listen_backlog);
	if (ret == -1)
	{
		LOG_FATAL("hub_start_service(): Unable to listen to socket");
		hub_free(hub);
		net_close(server_tcp);
		return 0;
	}

#ifdef SSL_SUPPORT
	if (config->tls_enable)
	{
		hub->ssl_method = SSLv23_method(); /* TLSv1_method() */
		hub->ssl_ctx = SSL_CTX_new(hub->ssl_method);

		/* Disable SSLv2 */
		SSL_CTX_set_options(hub->ssl_ctx, SSL_OP_NO_SSLv2);

		if (SSL_CTX_use_certificate_file(hub->ssl_ctx, config->tls_certificate, SSL_FILETYPE_PEM) < 0)
		{
			LOG_ERROR("SSL_CTX_use_certificate_file: %s", ERR_error_string(ERR_get_error(), NULL));
		}

		if (SSL_CTX_use_PrivateKey_file(hub->ssl_ctx, config->tls_private_key, SSL_FILETYPE_PEM) < 0)
		{
			LOG_ERROR("SSL_CTX_use_PrivateKey_file: %s", ERR_error_string(ERR_get_error(), NULL));
		}

		if (SSL_CTX_check_private_key(hub->ssl_ctx) != 1)
		{
			LOG_FATAL("SSL_CTX_check_private_key: Private key does not match the certificate public key: %s", ERR_error_string(ERR_get_error(), NULL));
			return 0;
		}
		LOG_INFO("Enabling TLS, using certificate: %s, private key: %s", config->tls_certificate, config->tls_private_key);
	}
#endif


	hub->config = config;
	hub->users = NULL;

	if (uman_init(hub) == -1)
	{
		hub_free(hub);
		net_close(server_tcp);
		return 0;
	}

	if (event_queue_initialize(&hub->queue, hub_event_dispatcher, (void*) hub) == -1)
	{
		uman_shutdown(hub);
		hub_free(hub);
		net_close(server_tcp);
		return 0;
	}

	hub->recvbuf = hub_malloc(MAX_RECV_BUF);
	hub->sendbuf = hub_malloc(MAX_SEND_BUF);
	if (!hub->recvbuf || !hub->sendbuf)
	{
		hub_free(hub->recvbuf);
		hub_free(hub->sendbuf);
		uman_shutdown(hub);
		hub_free(hub);
		net_close(server_tcp);
		return 0;
	}

	hub->chat_history = (struct linked_list*) list_create();
	hub->logout_info  = (struct linked_list*) list_create();
	if (!hub->chat_history)
	{
		list_destroy(hub->chat_history);
		list_destroy(hub->logout_info);
		hub_free(hub->recvbuf);
		hub_free(hub->sendbuf);
		uman_shutdown(hub);
		hub_free(hub);
		net_close(server_tcp);
		return 0;
	}

	hub->status = hub_status_running;

	hub->server = net_con_create();
	net_con_initialize(hub->server, server_tcp, net_on_accept, hub, NET_EVENT_READ);
	
	g_hub = hub;
	return hub;
}


void hub_shutdown_service(struct hub_info* hub)
{
	LOG_DEBUG("hub_shutdown_service()");

	event_queue_shutdown(hub->queue);
#ifdef USE_LIBEVENT
	event_del(&hub->ev_accept);
#endif
	net_con_close(hub->server);
	hub_free(hub->server);
	uman_shutdown(hub);
	hub->status = hub_status_stopped;
	hub_free(hub->sendbuf);
	hub_free(hub->recvbuf);
	hub_chat_history_clear(hub);
	list_destroy(hub->chat_history);
	list_clear(hub->logout_info, &hub_free);
	list_destroy(hub->logout_info);
	hub_free(hub);
	hub = 0;
	g_hub = 0;
}

#define SERVER "" PRODUCT "/" VERSION ""

void hub_set_variables(struct hub_info* hub, struct acl_handle* acl)
{
	int fd, ret;
	char buf[MAX_RECV_BUF];
	char* tmp;
	char* server = adc_msg_escape(SERVER); /* FIXME: OOM */
	
	hub->acl = acl;
	hub->command_info = adc_msg_construct(ADC_CMD_IINF, 15 + strlen(server));
	if (hub->command_info)
	{
		adc_msg_add_named_argument(hub->command_info, ADC_INF_FLAG_CLIENT_TYPE, ADC_CLIENT_TYPE_HUB);
		adc_msg_add_named_argument(hub->command_info, ADC_INF_FLAG_USER_AGENT, server);
	
		tmp = adc_msg_escape(hub->config->hub_name);
		adc_msg_add_named_argument(hub->command_info, ADC_INF_FLAG_NICK, tmp);
		hub_free(tmp);
	
		tmp = adc_msg_escape(hub->config->hub_description);
		adc_msg_add_named_argument(hub->command_info, ADC_INF_FLAG_DESCRIPTION, tmp);
		hub_free(tmp);
	}

	/* (Re-)read the message of the day */
	hub->command_motd = 0;
	fd = (hub->config->file_motd && *hub->config->file_motd) ? open(hub->config->file_motd, 0) : -1;
	if (fd != -1)
	{
		ret = read(fd, buf, MAX_RECV_BUF);
		if (ret > 0)
		{
			buf[ret] = 0;
			tmp = adc_msg_escape(buf);
			hub->command_motd = adc_msg_construct(ADC_CMD_IMSG, 6 + strlen(tmp));
			adc_msg_add_argument(hub->command_motd, tmp);
			hub_free(tmp);
		}
		close(fd);
	}

	hub->command_support = adc_msg_construct(ADC_CMD_ISUP, 6 + strlen(ADC_PROTO_SUPPORT));
	if (hub->command_support)
	{
		adc_msg_add_argument(hub->command_support, ADC_PROTO_SUPPORT);
	}

	hub->command_banner = adc_msg_construct(ADC_CMD_ISTA, 25 + strlen(server));
	if (hub->command_banner)
	{
		tmp = adc_msg_escape("Powered by " SERVER);
		adc_msg_add_argument(hub->command_banner, "000");
		adc_msg_add_argument(hub->command_banner, tmp);
		hub_free(tmp);
	}

	hub->status = (hub->config->hub_enabled ? hub_status_running : hub_status_disabled);
	hub_free(server);
}


void hub_free_variables(struct hub_info* hub)
{
	adc_msg_free(hub->command_info);
	adc_msg_free(hub->command_banner);

	if (hub->command_motd)
		adc_msg_free(hub->command_motd);

	adc_msg_free(hub->command_support);
}


/**
 * @return 1 if nickname is in use, or 0 if not used.
 */
static inline int is_nick_in_use(struct hub_info* hub, const char* nick)
{
	struct hub_user* lookup = uman_get_user_by_nick(hub, nick);
	if (lookup)
	{
		return 1;
	}
	return 0;
}


/**
 * @return 1 if CID is in use, or 0 if not used.
 */
static inline int is_cid_in_use(struct hub_info* hub, const char* cid)
{
	struct hub_user* lookup = uman_get_user_by_cid(hub, cid);
	if (lookup)
	{
		return 1;
	}
	return 0;
}




static void set_status_code(enum msg_status_level level, int code, char buffer[4])
{
	buffer[0] = ('0' + (int) level);
	buffer[1] = ('0' + (code / 10));
	buffer[2] = ('0' + (code % 10));
	buffer[3] = 0;
}

/**
 * @param hub The hub instance this message is sent from.
 * @param user The user this message is sent to.
 * @param msg See enum status_message
 * @param level See enum status_level
 */
void hub_send_status(struct hub_info* hub, struct hub_user* user, enum status_message msg, enum msg_status_level level)
{
	struct hub_config* cfg = hub->config;
	struct adc_message* cmd = adc_msg_construct(ADC_CMD_ISTA, 6);
	if (!cmd) return;
	char code[4];
	const char* text = 0;
	const char* flag = 0;
	char* escaped_text = 0;
	
#define STATUS(CODE, MSG, FLAG) case status_ ## MSG : set_status_code(level, CODE, code); text = cfg->MSG; flag = FLAG; break
	switch (msg)
	{
		STATUS(11, msg_hub_full, 0);
		STATUS(12, msg_hub_disabled, 0);
		STATUS(26, msg_hub_registered_users_only, 0);
		STATUS(43, msg_inf_error_nick_missing, 0);
		STATUS(43, msg_inf_error_nick_multiple, 0);
		STATUS(21, msg_inf_error_nick_invalid, 0);
		STATUS(21, msg_inf_error_nick_long, 0);
		STATUS(21, msg_inf_error_nick_short, 0);
		STATUS(21, msg_inf_error_nick_spaces, 0);
		STATUS(21, msg_inf_error_nick_bad_chars, 0);
		STATUS(21, msg_inf_error_nick_not_utf8, 0);
		STATUS(22, msg_inf_error_nick_taken, 0);
		STATUS(21, msg_inf_error_nick_restricted, 0);
		STATUS(43, msg_inf_error_cid_invalid, "FBID");
		STATUS(43, msg_inf_error_cid_missing, "FMID");
		STATUS(24, msg_inf_error_cid_taken, 0);
		STATUS(43, msg_inf_error_pid_missing, "FMPD");
		STATUS(27, msg_inf_error_pid_invalid, "FBPD");
		STATUS(31, msg_ban_permanently, 0);
		STATUS(32, msg_ban_temporarily, "TL600"); /* FIXME: Use a proper timeout */
		STATUS(23, msg_auth_invalid_password, 0);
		STATUS(20, msg_auth_user_not_found, 0);
		STATUS(30, msg_error_no_memory, 0);
		STATUS(43, msg_user_share_size_low,   "FB" ADC_INF_FLAG_SHARED_SIZE);
		STATUS(43, msg_user_share_size_high,  "FB" ADC_INF_FLAG_SHARED_SIZE);
		STATUS(43, msg_user_slots_low,        "FB" ADC_INF_FLAG_UPLOAD_SLOTS);
		STATUS(43, msg_user_slots_high,       "FB" ADC_INF_FLAG_UPLOAD_SLOTS);
		STATUS(43, msg_user_hub_limit_low, 0);
		STATUS(43, msg_user_hub_limit_high, 0);
	}
#undef STATUS
	
	escaped_text = adc_msg_escape(text);
	
	adc_msg_add_argument(cmd, code);
	adc_msg_add_argument(cmd, escaped_text);
	
	hub_free(escaped_text);
	
	if (flag)
	{
		adc_msg_add_argument(cmd, flag);
	}
	
	route_to_user(hub, user, cmd);
	adc_msg_free(cmd);
	
}

const char* hub_get_status_message(struct hub_info* hub, enum status_message msg)
{
#define STATUS(MSG) case status_ ## MSG : return cfg->MSG; break
	struct hub_config* cfg = hub->config;
	switch (msg)
	{
		STATUS(msg_hub_full);
		STATUS(msg_hub_disabled);
		STATUS(msg_hub_registered_users_only);
		STATUS(msg_inf_error_nick_missing);
		STATUS(msg_inf_error_nick_multiple);
		STATUS(msg_inf_error_nick_invalid);
		STATUS(msg_inf_error_nick_long);
		STATUS(msg_inf_error_nick_short);
		STATUS(msg_inf_error_nick_spaces);
		STATUS(msg_inf_error_nick_bad_chars);
		STATUS(msg_inf_error_nick_not_utf8);
		STATUS(msg_inf_error_nick_taken);
		STATUS(msg_inf_error_nick_restricted);
		STATUS(msg_inf_error_cid_invalid);
		STATUS(msg_inf_error_cid_missing);
		STATUS(msg_inf_error_cid_taken);
		STATUS(msg_inf_error_pid_missing);
		STATUS(msg_inf_error_pid_invalid);
		STATUS(msg_ban_permanently);
		STATUS(msg_ban_temporarily);
		STATUS(msg_auth_invalid_password);
		STATUS(msg_auth_user_not_found);
		STATUS(msg_error_no_memory);
		STATUS(msg_user_share_size_low);
		STATUS(msg_user_share_size_high);
		STATUS(msg_user_slots_low);
		STATUS(msg_user_slots_high);
		STATUS(msg_user_hub_limit_low);
		STATUS(msg_user_hub_limit_high);
	}
#undef STATUS
	return "Unknown";
}

const char* hub_get_status_message_log(struct hub_info* hub, enum status_message msg)
{
#define STATUS(MSG) case status_ ## MSG : return #MSG; break
        switch (msg)
        {
                STATUS(msg_hub_full);
                STATUS(msg_hub_disabled);
                STATUS(msg_hub_registered_users_only);
                STATUS(msg_inf_error_nick_missing);
                STATUS(msg_inf_error_nick_multiple);
                STATUS(msg_inf_error_nick_invalid);
                STATUS(msg_inf_error_nick_long);
                STATUS(msg_inf_error_nick_short);
                STATUS(msg_inf_error_nick_spaces);
                STATUS(msg_inf_error_nick_bad_chars);
                STATUS(msg_inf_error_nick_not_utf8);
                STATUS(msg_inf_error_nick_taken);
                STATUS(msg_inf_error_nick_restricted);
                STATUS(msg_inf_error_cid_invalid);
                STATUS(msg_inf_error_cid_missing);
                STATUS(msg_inf_error_cid_taken);
                STATUS(msg_inf_error_pid_missing);
                STATUS(msg_inf_error_pid_invalid);
                STATUS(msg_ban_permanently);
                STATUS(msg_ban_temporarily);
                STATUS(msg_auth_invalid_password);
                STATUS(msg_auth_user_not_found);
                STATUS(msg_error_no_memory);
                STATUS(msg_user_share_size_low);
                STATUS(msg_user_share_size_high);
                STATUS(msg_user_slots_low);
                STATUS(msg_user_slots_high);
                STATUS(msg_user_hub_limit_low);
                STATUS(msg_user_hub_limit_high);
        }
#undef STATUS
        return "unknown";
}


size_t hub_get_user_count(struct hub_info* hub)
{
	return hub->users->count;
}

size_t hub_get_max_user_count(struct hub_info* hub)
{
	return hub->config->max_users;
}

uint64_t hub_get_shared_size(struct hub_info* hub)
{
	return hub->users->shared_size;
}

uint64_t hub_get_shared_files(struct hub_info* hub)
{
	return hub->users->shared_files;
}

uint64_t hub_get_min_share(struct hub_info* hub)
{
	return 1024 * 1024 * hub->config->limit_min_share;
}

uint64_t hub_get_max_share(struct hub_info* hub)
{
	return 1024 * 1024 * hub->config->limit_max_share;
}

size_t hub_get_min_slots(struct hub_info* hub)
{
	return hub->config->limit_min_slots;
}

size_t hub_get_max_slots(struct hub_info* hub)
{
	return hub->config->limit_max_slots;
}

size_t hub_get_max_hubs_total(struct hub_info* hub)
{
	return hub->config->limit_max_hubs;
}

size_t hub_get_max_hubs_user(struct hub_info* hub)
{
	return hub->config->limit_max_hubs_user;
}

size_t hub_get_min_hubs_user(struct hub_info* hub)
{
	return hub->config->limit_min_hubs_user;
}

size_t hub_get_max_hubs_reg(struct hub_info* hub)
{
	return hub->config->limit_max_hubs_reg;
}

size_t hub_get_min_hubs_reg(struct hub_info* hub)
{
	return hub->config->limit_min_hubs_reg;
}

size_t hub_get_max_hubs_op(struct hub_info* hub)
{
	return hub->config->limit_max_hubs_op;
}

size_t hub_get_min_hubs_op(struct hub_info* hub)
{
	return hub->config->limit_min_hubs_op;
}

void hub_schedule_destroy_user(struct hub_info* hub, struct hub_user* user)
{
	struct event_data post;
	memset(&post, 0, sizeof(post));
	post.id = UHUB_EVENT_USER_DESTROY;
	post.ptr = user;
	event_queue_post(hub->queue, &post);

	if (user->id.sid)
	{
		sid_free(hub->users->sids, user->id.sid);
	}
}

void hub_disconnect_all(struct hub_info* hub)
{
	struct event_data post;
	memset(&post, 0, sizeof(post));
	post.id = UHUB_EVENT_HUB_SHUTDOWN;
	post.ptr = 0;
	event_queue_post(hub->queue, &post);
}

void hub_event_loop(struct hub_info* hub)
{
	do
	{
		net_backend_process();
		event_queue_process(hub->queue);
	}
	while (hub->status == hub_status_running || hub->status == hub_status_disabled);
	

	if (hub->status == hub_status_shutdown)
	{
		LOG_DEBUG("Removing all users...");
		event_queue_process(hub->queue);
		event_queue_process(hub->queue);
		hub_disconnect_all(hub);
		event_queue_process(hub->queue);
		hub->status = hub_status_stopped;
	}
}


void hub_disconnect_user(struct hub_info* hub, struct hub_user* user, int reason)
{
	struct event_data post;
	int need_notify = 0;

	/* is user already being disconnected ? */
	if (user_is_disconnecting(user))
	{
		return;
	}

	/* stop reading from user */
	net_shutdown_r(net_con_get_sd(user->connection));
	net_con_close(user->connection);
	user->connection = 0;

	LOG_TRACE("hub_disconnect_user(), user=%p, reason=%d, state=%d", user, reason, user->state);
	
	need_notify = user_is_logged_in(user) && hub->status == hub_status_running;
	user->quit_reason = reason;
	user_set_state(user, state_cleanup);
	
	if (need_notify)
	{
		memset(&post, 0, sizeof(post));
		post.id     = UHUB_EVENT_USER_QUIT;
		post.ptr    = user;
		event_queue_post(hub->queue, &post);
	}
	else
	{
		hub_schedule_destroy_user(hub, user);
	}
}

void hub_logout_log(struct hub_info* hub, struct hub_user* user)
{
	struct hub_logout_info* loginfo = hub_malloc_zero(sizeof(struct hub_logout_info));
	if (!loginfo) return;
	loginfo->time = time(NULL);
	strcpy(loginfo->cid, user->id.cid);
	strcpy(loginfo->nick, user->id.nick);
	memcpy(&loginfo->addr, &user->id.addr, sizeof(struct ip_addr_encap));
	loginfo->reason = user->quit_reason;

	list_append(hub->logout_info, loginfo);
	while (list_size(hub->logout_info) > (size_t) hub->config->max_logout_log)
	{
		struct hub_logout_info* entry = list_get_first(hub->logout_info);
		list_remove(hub->logout_info, entry);
		hub_free(entry);
	}
}

