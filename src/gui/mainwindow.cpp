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

#include "gui/mainwindow.h"
#include "gui/netclient.h"
#include "gui/adcbridge.h"

#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QListWidget>
#include <QLabel>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QSplitter>
#include <QStatusBar>
#include <QScrollBar>

MainWindow::MainWindow(QWidget* parent)
	: QMainWindow(parent), m_connected(false)
{
	m_client = new NetClient(this);

	/* --- connection bar --- */
	m_address = new QLineEdit("adc://127.0.0.1:1511");
	m_nick    = new QLineEdit("uhub-qt");
	m_nick->setMaximumWidth(140);
	m_password = new QLineEdit;
	m_password->setEchoMode(QLineEdit::Password);
	m_password->setPlaceholderText("password (optional)");
	m_password->setMaximumWidth(160);
	m_connect = new QPushButton("Connect");

	QHBoxLayout* top = new QHBoxLayout;
	top->addWidget(new QLabel("Hub:"));
	top->addWidget(m_address, 1);
	top->addWidget(new QLabel("Nick:"));
	top->addWidget(m_nick);
	top->addWidget(m_password);
	top->addWidget(m_connect);

	/* --- chat + user list --- */
	m_chat = new QTextEdit;
	m_chat->setReadOnly(true);
	m_users = new QListWidget;
	m_users->setMinimumWidth(180);

	QSplitter* split = new QSplitter(Qt::Horizontal);
	split->addWidget(m_chat);
	split->addWidget(m_users);
	split->setStretchFactor(0, 1);
	split->setStretchFactor(1, 0);

	/* --- input --- */
	m_input = new QLineEdit;
	m_input->setPlaceholderText("Message, or /me, /msg <nick> <text>, /search <terms>");
	m_input->setEnabled(false);
	m_send = new QPushButton("Send");
	m_send->setEnabled(false);

	QHBoxLayout* bottom = new QHBoxLayout;
	bottom->addWidget(m_input, 1);
	bottom->addWidget(m_send);

	QVBoxLayout* root = new QVBoxLayout;
	root->addLayout(top);
	root->addWidget(split, 1);
	root->addLayout(bottom);

	QWidget* central = new QWidget;
	central->setLayout(root);
	setCentralWidget(central);

	m_status = new QLabel("Not connected");
	statusBar()->addWidget(m_status);

	setWindowTitle("uhub-qt");
	resize(820, 560);

	/* --- wiring --- */
	connect(m_connect, &QPushButton::clicked, this, &MainWindow::onConnectClicked);
	connect(m_send, &QPushButton::clicked, this, &MainWindow::onSendClicked);
	connect(m_input, &QLineEdit::returnPressed, this, &MainWindow::onSendClicked);
	connect(m_users, &QListWidget::itemActivated, this, &MainWindow::onUserActivated);

	connect(m_client, &NetClient::stateChanged,    this, &MainWindow::onStateChanged);
	connect(m_client, &NetClient::loginError,      this, &MainWindow::onLoginError);
	connect(m_client, &NetClient::sslEstablished,  this, &MainWindow::onSslEstablished);
	connect(m_client, &NetClient::hubInfo,         this, &MainWindow::onHubInfo);
	connect(m_client, &NetClient::statusMessage,   this, &MainWindow::onStatusMessage);
	connect(m_client, &NetClient::chatReceived,    this, &MainWindow::onChatReceived);
	connect(m_client, &NetClient::userJoined,      this, &MainWindow::onUserJoined);
	connect(m_client, &NetClient::userUpdated,     this, &MainWindow::onUserUpdated);
	connect(m_client, &NetClient::userQuit,        this, &MainWindow::onUserQuit);
}

/* ------------------------------------------------------------------ */

void MainWindow::appendChat(const QString& html)
{
	m_chat->append(html);
	QScrollBar* bar = m_chat->verticalScrollBar();
	bar->setValue(bar->maximum());
}

void MainWindow::appendSystem(const QString& text)
{
	appendChat(QString("<span style='color:#888'>*** %1</span>").arg(text.toHtmlEscaped()));
}

void MainWindow::setConnectedUi(bool connected)
{
	m_connected = connected;
	m_connect->setText(connected ? "Disconnect" : "Connect");
	m_input->setEnabled(connected);
	m_send->setEnabled(connected);
	m_address->setEnabled(!connected);
	m_nick->setEnabled(!connected);
	m_password->setEnabled(!connected);
	if (!connected)
	{
		m_users->clear();
		m_userItems.clear();
	}
}

void MainWindow::upsertUser(quint32 sid, const QString& nick, bool isOp, bool isBot, const QString& address)
{
	QString label = nick.isEmpty() ? QString("(sid %1)").arg(sid) : nick;
	if (isOp)
		label.prepend("@");
	else if (isBot)
		label.prepend("$");

	QListWidgetItem* item = m_userItems.value(sid, nullptr);
	if (!item)
	{
		item = new QListWidgetItem(m_users);
		m_userItems.insert(sid, item);
	}
	item->setText(label);
	item->setData(Qt::UserRole, sid);
	item->setData(Qt::UserRole + 1, nick);
	item->setToolTip(address.isEmpty() ? nick : QString("%1 (%2)").arg(nick, address));
}

void MainWindow::connectTo(const QString& url)
{
	m_address->setText(url);
	onConnectClicked();
}

/* ------------------------------------------------------------------ */

void MainWindow::onConnectClicked()
{
	if (m_connected)
	{
		m_client->disconnectHub();
		return;
	}
	appendSystem(QString("Connecting to %1 ...").arg(m_address->text()));
	m_client->connectHub(m_address->text(), m_nick->text(), m_password->text());
}

void MainWindow::onSendClicked()
{
	const QString line = m_input->text();
	if (line.isEmpty())
		return;
	m_input->clear();

	if (line.startsWith('/'))
	{
		const int sp = line.indexOf(' ');
		const QString cmd = line.mid(1, (sp < 0 ? line.size() : sp) - 1);
		const QString rest = sp < 0 ? QString() : line.mid(sp + 1);

		if (cmd == "me")
		{
			m_client->sayMe(rest);
		}
		else if (cmd == "search")
		{
			m_client->search(rest);
			appendSystem(QString("Searching: %1").arg(rest));
		}
		else if (cmd == "msg" || cmd == "pm")
		{
			const int sp2 = rest.indexOf(' ');
			if (sp2 < 0)
			{
				appendSystem("Usage: /msg <nick> <text>");
				return;
			}
			const QString target = rest.left(sp2);
			const QString text = rest.mid(sp2 + 1);
			quint32 sid = 0;
			for (auto it = m_userItems.constBegin(); it != m_userItems.constEnd(); ++it)
			{
				if (it.value()->data(Qt::UserRole + 1).toString() == target)
				{
					sid = it.key();
					break;
				}
			}
			if (!sid)
				appendSystem(QString("No such user: %1").arg(target));
			else
			{
				m_client->pm(sid, text);
				appendChat(QString("<span style='color:#a0a'>[PM to %1]</span> %2")
					.arg(target.toHtmlEscaped(), text.toHtmlEscaped()));
			}
		}
		else if (cmd == "quit")
		{
			m_client->disconnectHub();
		}
		else
		{
			appendSystem(QString("Unknown command: /%1").arg(cmd));
		}
	}
	else
	{
		m_client->say(line);
	}
}

void MainWindow::onUserActivated(QListWidgetItem* item)
{
	const QString nick = item->data(Qt::UserRole + 1).toString();
	if (nick.isEmpty())
		return;
	m_input->setText(QString("/msg %1 ").arg(nick));
	m_input->setFocus();
}

/* ---- NetClient signals ---- */

void MainWindow::onStateChanged(int state)
{
	switch (state)
	{
		case ADCBRIDGE_CONNECTING:    m_status->setText("Connecting..."); break;
		case ADCBRIDGE_CONNECTED:     m_status->setText("Connected"); appendSystem("Connected."); break;
		case ADCBRIDGE_SSL_HANDSHAKE: m_status->setText("TLS handshake..."); break;
		case ADCBRIDGE_LOGGING_IN:    m_status->setText("Logging in..."); break;
		case ADCBRIDGE_LOGGED_IN:
			m_status->setText("Logged in");
			appendSystem("Logged in.");
			setConnectedUi(true);
			break;
		case ADCBRIDGE_DISCONNECTED:
			m_status->setText("Disconnected");
			appendSystem("Disconnected.");
			setConnectedUi(false);
			break;
	}
}

void MainWindow::onLoginError(int code, const QString& message)
{
	appendSystem(QString("Login error %1: %2").arg(code, 3, 10, QChar('0')).arg(message));
}

void MainWindow::onSslEstablished(const QString& version, const QString& cipher)
{
	appendSystem(QString("TLS: %1 / %2").arg(version, cipher));
}

void MainWindow::onHubInfo(const QString& name, const QString& version, const QString& description)
{
	setWindowTitle(QString("uhub-qt - %1").arg(name));
	appendSystem(QString("Hub: %1 [%2] - %3").arg(name, version, description));
}

void MainWindow::onStatusMessage(int code, const QString& message)
{
	appendSystem(QString("Status %1: %2").arg(code, 3, 10, QChar('0')).arg(message));
}

void MainWindow::onChatReceived(quint32 fromSid, const QString& fromNick, const QString& text, int flags)
{
	Q_UNUSED(fromSid);
	const bool priv = (flags & ADCBRIDGE_CHAT_PRIVATE) != 0;
	const bool action = (flags & ADCBRIDGE_CHAT_ACTION) != 0;
	const QString who = fromNick.isEmpty() ? QString("HUB") : fromNick.toHtmlEscaped();
	const QString body = text.toHtmlEscaped();

	if (action)
		appendChat(QString("<i>* %1 %2</i>").arg(who, body));
	else if (priv)
		appendChat(QString("<span style='color:#a0a'>[PM] &lt;%1&gt;</span> %2").arg(who, body));
	else
		appendChat(QString("<b>&lt;%1&gt;</b> %2").arg(who, body));
}

void MainWindow::onUserJoined(quint32 sid, const QString& nick, const QString& description,
                              const QString& address, bool isOp, bool isBot)
{
	Q_UNUSED(description);
	upsertUser(sid, nick, isOp, isBot, address);
}

void MainWindow::onUserUpdated(quint32 sid, const QString& nick, const QString& description,
                               const QString& address, bool isOp, bool isBot)
{
	Q_UNUSED(description);
	upsertUser(sid, nick, isOp, isBot, address);
}

void MainWindow::onUserQuit(quint32 sid, const QString& nick)
{
	Q_UNUSED(nick);
	QListWidgetItem* item = m_userItems.value(sid, nullptr);
	if (item)
	{
		m_userItems.remove(sid);
		delete item;
	}
}
