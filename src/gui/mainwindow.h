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

#ifndef HAVE_UHUB_GUI_MAINWINDOW_H
#define HAVE_UHUB_GUI_MAINWINDOW_H

#include <QMainWindow>
#include <QHash>

class NetClient;
class QLineEdit;
class QPushButton;
class QTextEdit;
class QListWidget;
class QListWidgetItem;
class QLabel;

class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
	explicit MainWindow(QWidget* parent = nullptr);

	/* Prefill the hub address and connect (used for an adc[s]:// URL passed
	   on the command line). */
	void connectTo(const QString& url);

private slots:
	void onConnectClicked();
	void onSendClicked();
	void onUserActivated(QListWidgetItem* item);

	/* from NetClient (queued) */
	void onStateChanged(int state);
	void onLoginError(int code, const QString& message);
	void onSslEstablished(const QString& version, const QString& cipher);
	void onHubInfo(const QString& name, const QString& version, const QString& description);
	void onStatusMessage(int code, const QString& message);
	void onChatReceived(quint32 fromSid, const QString& fromNick, const QString& text, int flags);
	void onUserJoined(quint32 sid, const QString& nick, const QString& description,
	                  const QString& address, bool isOp, bool isBot);
	void onUserUpdated(quint32 sid, const QString& nick, const QString& description,
	                   const QString& address, bool isOp, bool isBot);
	void onUserQuit(quint32 sid, const QString& nick);

private:
	void appendChat(const QString& html);
	void appendSystem(const QString& text);
	void setConnectedUi(bool connected);
	void upsertUser(quint32 sid, const QString& nick, bool isOp, bool isBot, const QString& address);

	NetClient*   m_client;

	QLineEdit*   m_address;
	QLineEdit*   m_nick;
	QLineEdit*   m_password;
	QPushButton* m_connect;
	QTextEdit*   m_chat;
	QListWidget* m_users;
	QLineEdit*   m_input;
	QPushButton* m_send;
	QLabel*      m_status;

	QHash<quint32, QListWidgetItem*> m_userItems;
	bool m_connected;
};

#endif /* HAVE_UHUB_GUI_MAINWINDOW_H */
