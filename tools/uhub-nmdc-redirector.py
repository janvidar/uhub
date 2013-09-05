#!/usr/bin/env python
"""
A simple NMDC to ADC redirector service.
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

class NmdcRedirector(SocketServer.BaseRequestHandler):

	def setup(self):
		self.request.sendall("<%(botname)s> %(message)s|$ForceMove %(address)s|" % { "address": redirect_uri, "botname": bot_name, "message": message })
		return False

if __name__ == "__main__":
	server = SocketServer.TCPServer((bind_addr, bind_port), NmdcRedirector)
	server.allow_reuse_address = True
	server.serve_forever()
