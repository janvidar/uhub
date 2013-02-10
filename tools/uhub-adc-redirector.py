#!/usr/bin/env python
"""
A simple ADC redirector service.
"""

import SocketServer

# The target hub we want to redirect clients to
redirect_uri = "adcs://adcs.uhub.org:1511"

# A message to be sent to users while they are being redirected.
message = "This hub has been permanently moved."

# The chat name of the message.
bot_name = "Redirector"

# The local address and port to bind the redirector to.
bind_addr = "0.0.0.0"
bind_port = 1411

class AdcRedirector(SocketServer.BaseRequestHandler):

	def escape(self, str):
		modified = str.replace("\\", "\\\\").replace(" ", "\\s").replace("\n", "\\n")
		return modified;

	def handle(self):
		supports = False;
		while True:
			data = self.request.recv(1024)
			if (data.startswith("HSUP") and not supports):
				self.request.sendall("ISUP ADBASE ADTIGR\nISID AAAX\nIINF CT32 NI%(botname)s VEuhub-adc-redirector/0.1\n" % { "address": redirect_uri, "botname": self.escape(bot_name), "message": self.escape(message) })
				supports = True
			elif (data.startswith("BINF") and supports):
				self.request.sendall("IMSG %(message)s\nIQUI AAAX RD%(address)s\n" % {"message": self.escape(message), "address": redirect_uri })
				break
			else:
				break

if __name__ == "__main__":
	server = SocketServer.TCPServer((bind_addr, bind_port), AdcRedirector)
	server.allow_reuse_address = True
	server.serve_forever()
