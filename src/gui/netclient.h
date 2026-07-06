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

#ifndef HAVE_UHUB_GUI_NETCLIENT_H
#define HAVE_UHUB_GUI_NETCLIENT_H

#include <QObject>
#include <QString>

#include "gui/adcbridge.h"

/*
 * NetClient owns an adcbridge and turns its reactor-thread callbacks into
 * Qt signals. Because the bridge callbacks fire on the reactor thread and
 * the connected slots live on the GUI thread, Qt delivers them as queued
 * signals -- so all UI code stays single-threaded. Outbound methods forward
 * straight to the (thread-safe) bridge.
 */
class NetClient : public QObject
{
	Q_OBJECT

public:
	explicit NetClient(QObject* parent = nullptr);
	~NetClient() override;

public slots:
	void connectHub(const QString& address, const QString& nick, const QString& password);
	void disconnectHub();
	void say(const QString& text);
	void sayMe(const QString& text);
	void pm(quint32 sid, const QString& text);
	void search(const QString& terms);

signals:
	void stateChanged(int state);
	void loginError(int code, const QString& message);
	void sslEstablished(const QString& version, const QString& cipher);
	void hubInfo(const QString& name, const QString& version, const QString& description);
	void statusMessage(int code, const QString& message);
	void chatReceived(quint32 fromSid, const QString& fromNick, const QString& text, int flags);
	void userJoined(quint32 sid, const QString& nick, const QString& description,
	                const QString& address, bool isOp, bool isBot);
	void userUpdated(quint32 sid, const QString& nick, const QString& description,
	                 const QString& address, bool isOp, bool isBot);
	void userQuit(quint32 sid, const QString& nick);
	void logLine(const QString& line);

private:
	/* C-callable trampolines; `user` is the NetClient* passed to the bridge. */
	static void cbState(void* user, int state);
	static void cbLoginError(void* user, int code, const char* message);
	static void cbSslOk(void* user, const char* version, const char* cipher);
	static void cbHubInfo(void* user, const char* name, const char* version, const char* description);
	static void cbStatus(void* user, int code, const char* message);
	static void cbChat(void* user, uint32_t sid, const char* nick, const char* text, int flags);
	static void cbUserJoin(void* user, const struct adcbridge_user* u);
	static void cbUserUpdate(void* user, const struct adcbridge_user* u);
	static void cbUserQuit(void* user, uint32_t sid, const char* nick);
	static void cbLog(void* user, const char* line);

	adcbridge* m_bridge;
};

#endif /* HAVE_UHUB_GUI_NETCLIENT_H */
