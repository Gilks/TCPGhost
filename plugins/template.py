#!/usr/bin/env python3
#
#  Copyright 2017 Corey Gilks <CoreyGilks [at] gmail [dot] com>
#  Twitter: @CoreyGilks
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.

from tcpghost import TCPGhost


class TCPGhostPlugin(TCPGhost):
	def client_socket_setup(self, sockt):
		'''
		This method is called once when a new client connects. You may tweak the client socket anyway you see fit as
		long as you return the socket when you are finished.

		If you want to serve clients with the cert specified under the --cert/--key arguments you can do so like this:

		sockt = self.create_secure_socket(sockt, use_certs=True)
		'''
		self.log.info("Here we can configure the client socket options")
		return sockt

	def server_socket_setup(self, sockt):
		'''
		This method is called once when a new client connects. You may tweak the client socket anyway you see fit as
		long as you return the socket when you are finished.

		If you want use SSL and connect to your remote target, you can do so like this:
		sockt = self.create_secure_socket(sockt, connect=True)

		If you just want to establish the socket (but don't want to connect yet), you can do so like this:
		sockt = self.create_secure_socket(sockt)
		'''
		# Called once. Gives plugins the ability to configure sockets in a specific way (ex. TLS)
		self.log.info("Here we can configure the server socket options")
		return sockt

	def server_buffer(self, buffer):
		# Called each time the server responds. This buffer is on its way to the client.
		self.log.info("Template plugin reporting in from server_buffer")
		return buffer

	def client_buffer(self, buffer):
		# Called each time the client responds. This buffer is on its way to the server.
		self.log.info("Template plugin reporting in from client_buffer")
		return buffer
