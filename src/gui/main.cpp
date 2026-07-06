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
 * uhub-qt -- a minimal Qt reference client for the uhub ADC client library.
 * It exists to demonstrate the GUI seam (gui/adcbridge.h): a frontend never
 * touches the ADC wire protocol, only the typed intent API behind the bridge.
 */

#include <QApplication>
#include <QString>
#include "gui/mainwindow.h"

int main(int argc, char** argv)
{
	QApplication app(argc, argv);
	MainWindow window;
	window.show();

	/* Optional: a hub URL on the command line prefills and auto-connects. */
	if (argc > 1)
	{
		const QString url = QString::fromUtf8(argv[1]);
		if (url.startsWith("adc://") || url.startsWith("adcs://"))
			window.connectTo(url);
	}

	return app.exec();
}
