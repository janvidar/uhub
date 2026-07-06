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

#include "gui/netclient.h"

static QString qstr(const char* s)
{
	return QString::fromUtf8(s ? s : "");
}

NetClient::NetClient(QObject* parent)
	: QObject(parent), m_bridge(nullptr)
{
	struct adcbridge_callbacks cb;
	memset(&cb, 0, sizeof(cb));
	cb.user           = this;
	cb.on_state       = &NetClient::cbState;
	cb.on_login_error = &NetClient::cbLoginError;
	cb.on_ssl_ok      = &NetClient::cbSslOk;
	cb.on_hub_info    = &NetClient::cbHubInfo;
	cb.on_status      = &NetClient::cbStatus;
	cb.on_chat        = &NetClient::cbChat;
	cb.on_user_join   = &NetClient::cbUserJoin;
	cb.on_user_update = &NetClient::cbUserUpdate;
	cb.on_user_quit   = &NetClient::cbUserQuit;
	cb.on_log         = &NetClient::cbLog;
	m_bridge = adcbridge_create(&cb);
}

NetClient::~NetClient()
{
	if (m_bridge)
		adcbridge_destroy(m_bridge);
}

/* ---- outbound (GUI thread -> bridge, which marshals to the reactor) ---- */

void NetClient::connectHub(const QString& address, const QString& nick, const QString& password)
{
	adcbridge_connect(m_bridge, address.toUtf8().constData(),
		nick.toUtf8().constData(), password.toUtf8().constData());
}

void NetClient::disconnectHub()               { adcbridge_disconnect(m_bridge); }
void NetClient::say(const QString& text)       { adcbridge_say(m_bridge, text.toUtf8().constData()); }
void NetClient::sayMe(const QString& text)     { adcbridge_say_me(m_bridge, text.toUtf8().constData()); }
void NetClient::search(const QString& terms)   { adcbridge_search(m_bridge, terms.toUtf8().constData()); }
void NetClient::pm(quint32 sid, const QString& text)
{
	adcbridge_pm(m_bridge, sid, text.toUtf8().constData());
}

/* ---- inbound trampolines (reactor thread -> queued signal -> GUI) ---- */

void NetClient::cbState(void* user, int state)
{
	emit static_cast<NetClient*>(user)->stateChanged(state);
}

void NetClient::cbLoginError(void* user, int code, const char* message)
{
	emit static_cast<NetClient*>(user)->loginError(code, qstr(message));
}

void NetClient::cbSslOk(void* user, const char* version, const char* cipher)
{
	emit static_cast<NetClient*>(user)->sslEstablished(qstr(version), qstr(cipher));
}

void NetClient::cbHubInfo(void* user, const char* name, const char* version, const char* description)
{
	emit static_cast<NetClient*>(user)->hubInfo(qstr(name), qstr(version), qstr(description));
}

void NetClient::cbStatus(void* user, int code, const char* message)
{
	emit static_cast<NetClient*>(user)->statusMessage(code, qstr(message));
}

void NetClient::cbChat(void* user, uint32_t sid, const char* nick, const char* text, int flags)
{
	emit static_cast<NetClient*>(user)->chatReceived(sid, qstr(nick), qstr(text), flags);
}

void NetClient::cbUserJoin(void* user, const struct adcbridge_user* u)
{
	emit static_cast<NetClient*>(user)->userJoined(u->sid, qstr(u->nick), qstr(u->description),
		qstr(u->address), u->is_op != 0, u->is_bot != 0);
}

void NetClient::cbUserUpdate(void* user, const struct adcbridge_user* u)
{
	emit static_cast<NetClient*>(user)->userUpdated(u->sid, qstr(u->nick), qstr(u->description),
		qstr(u->address), u->is_op != 0, u->is_bot != 0);
}

void NetClient::cbUserQuit(void* user, uint32_t sid, const char* nick)
{
	emit static_cast<NetClient*>(user)->userQuit(sid, qstr(nick));
}

void NetClient::cbLog(void* user, const char* line)
{
	emit static_cast<NetClient*>(user)->logLine(qstr(line));
}
