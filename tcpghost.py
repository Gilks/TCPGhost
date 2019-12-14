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

import socket
import select
import sys
import os
import argparse
import logging
import time
import threading
import random
import ssl
import plugins
import shutil
from importlib import util

version = "0.1"

try:
	from OpenSSL import SSL, crypto
except ImportError:
	print("You must install openssl for Python 3 before continuing. Try `pip3 install pyopenssl'")
	sys.exit(os.EX_SOFTWARE)

HELP_EPILOG = """
TCPGhost is a transparent proxy with TLS support. By default, socket connections are unencrypted. Encrypted sockets
can be created using plugins. See the plugins folder for a template example.
"""

class TCPGhost:
	def __init__(self, client_socket=None, rhost=None, rport=None, cert=None, key=None, force_verification=None, plugin=None):
		self.log = logging.getLogger('')
		self.cert = cert
		self.key = key
		self.tls_protocol = SSL.TLSv1_2_METHOD
		self.thread = None
		self.trusted_cert_store = None
		self.force_verification = force_verification
		self.rhost = rhost
		self.rport = rport
		self.module = plugin
		sockt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sockt.setblocking(False)
		if self.module:
			client_socket = self.module.TCPGhostPlugin.client_socket_setup(self, client_socket)
			server_socket = self.module.TCPGhostPlugin.server_socket_setup(self, sockt)
		else:
			server_socket = sockt
		try:
			server_socket.connect((self.rhost, self.rport))
		except BlockingIOError:
			pass
		self.client_socket = client_socket
		self.server_socket = server_socket

	@staticmethod
	def load_plugin(plugin):
		selected = '{0}{1}'.format(plugin, '.py').lower()
		plugin_not_found = True
		for plugin_path in plugins.modules:
			if not plugin_path.lower().endswith(selected):
				continue
			plugin_not_found = False
			spec = util.spec_from_file_location(plugin, plugin_path)
			module = util.module_from_spec(spec)
			sys.modules[spec.name] = module
			spec.loader.exec_module(module)
			break
		if plugin_not_found:
			logging.info("No plugin named '{0}' found in the plugins folder.".format(plugin))
			raise FileNotFoundError
		logging.info("Successfully loaded the plugin: {0}".format(plugin))
		return module

	def regular_socket_read(self, sockt, label):
		buffer_complete = b""
		terminate = False
		while True:
			try:
				buffer = sockt.recv(4096)
				if len(buffer):
					buffer_complete += buffer
				else:
					self.log.debug("{0} EOF".format(label))
					terminate = True
					break

			except BlockingIOError:
				self.log.debug("{0} buffer read".format(label))
				break

		return [buffer_complete, terminate]

	def secure_socket_read(self, sockt, label):
		buffer_complete = b""
		terminate = False
		while True:
			pending = 0
			try:
				pending = sockt.pending()
				buffer = sockt.read(4096)

			except (SSL.WantReadError, ssl.SSLWantReadError):
				if pending == 0:
					break
				continue

			except Exception as e:
				self.log.debug(e)
				terminate = True
				break

			self.log.debug("{0} secure socket buffer read".format(label))

			if len(buffer) > 0:
				buffer_complete += buffer

			else:
				self.log.debug("{0} secure socket EOF".format(label))
				terminate = True
				break
		return [buffer_complete, terminate]

	def relay(self):
		self.client_socket.setblocking(False)
		terminate = False

		while not terminate:
			buffer_client = b""
			buffer_server = b""
			inputs = [self.client_socket, self.server_socket]

			readable_sockets, writeable_sockets, error_sockets = select.select(inputs, [], [], 10.0)

			for readable_socket in readable_sockets:
				# There's two different options for each socket. They can be encrypted or unencrypted. Each type
				# of socket requires different actions.
				if readable_socket == self.client_socket:
					if not type(self.client_socket) == socket.socket:
						buffer_server, terminate = self.secure_socket_read(self.client_socket, 'client')
					else:
						buffer_server, terminate = self.regular_socket_read(self.client_socket, 'client')

				elif readable_socket == self.server_socket:
					if not type(self.server_socket) == socket.socket:
						buffer_client, terminate = self.secure_socket_read(self.server_socket, 'server')
					else:
						buffer_client, terminate = self.regular_socket_read(self.server_socket, 'server')

			if self.module:
				server_buffer_plugin = self.module.TCPGhostPlugin.server_buffer
				client_buffer_plugin = self.module.TCPGhostPlugin.client_buffer
			else:
				server_buffer_plugin = None
				client_buffer_plugin = None

			# This buffer is on its way to the client from the server
			self.send_all(self.client_socket, buffer_client, 'server', server_buffer_plugin)

			# This buffer is on its way to the server from the client
			self.send_all(self.server_socket, buffer_server, 'client', client_buffer_plugin)

	def send_all(self, sockt, buffer, data_from, plugin):
		while len(buffer):
			try:
				if plugin:
					buffer = plugin(self, buffer)
				if buffer:
					# If the plugin returns None, it does not want us to send.
					bytes_sent = sockt.send(buffer)
				else:
					break

			except SSL.WantReadError:
				# OpenSSL library. Occurs with non-blocking sockets.
				self.log.debug('openssl raised SSLWantReadError')
				continue

			except ssl.SSLWantReadError:
				# Python ssl library. Occurs with non-blocking sockets.
				self.log.debug('python ssl raised SSLWantReadError')
				continue

			except ssl.SSLWantWriteError:
				# Python ssl library. Occurs with non-blocking sockets.
				self.log.debug('python ssl raised SSLWantWriteError')
				continue

			except SSL.WantWriteError:
				# OpenSSL library. Occurs with non-blocking sockets.
				self.log.debug('openssl raised SSLWantWriteError')
				continue

			if len(buffer) > 500:
				display = buffer.decode('ISO-8859-1')[:500]
			else:
				display = buffer.decode('ISO-8859-1')
			self.log.info("From {0}:\n{1}\n".format(data_from, buffer.decode('ISO-8859-1')))

			if bytes_sent:
				buffer = buffer[bytes_sent:]

	def verify_cert(self, conn, cert, errnum, depth, ok):
		if self.force_verification:
			store_ctx = crypto.X509StoreContext(self.trusted_cert_store, cert)
			store_ctx.verify_certificate()
			self.log.debug("Server cert verified")
			return 1

		self.log.debug("Not verifying target server cert")
		return 1

	def create_secure_socket(self, sockt, use_certs=False, connect=False):
		if use_certs:
			if not self.cert or not self.key:
				raise FileNotFoundError("Cannot apply SSL to socket as no certificate or key was specified. Spoof one or specify a custom one.")

			secure_socket = ssl.wrap_socket(sockt,
											server_side=True,
											certfile=self.cert,
											keyfile=self.key,
											ssl_version=ssl.PROTOCOL_TLSv1_2,
											cert_reqs=ssl.CERT_NONE)

			try:
				secure_socket.do_handshake()
			except ssl.SSLERROR as e:
				self.log.debug("An SSL exception occured: {0}".format(e))

		else:
			try:
				ctx = SSL.Context(self.tls_protocol)
				secure_socket = SSL.Connection(ctx, sockt)
				if connect:
					secure_socket.connect((self.rhost, self.rport))
				sockt.setblocking(False)

			except ConnectionRefusedError:
				secure_socket.close()
				self.client_socket.close()
				raise ConnectionRefusedError('Connection refused on target {0}:{1}'.format(self.rhost, self.rport))

			except BlockingIOError:
				logging.debug("Blocking IO Error")
				pass

		return secure_socket

	def relay_and_cleanup(self):
		self.log.debug("Beginning client/server relay")
		try:
			self.relay()

		finally:
			self.server_socket.close()
			self.client_socket.close()
			self.log.info("Client disconnected. Killing: {0}".format(self.thread.name))

	@staticmethod
	def get_target_x509(url):
		'''
		Grab the SSL certificate from a target and return the x509 object

		:param url:
		:return: crypto x509 object
		'''
		if url.startswith('http://') or url.startswith('https://'):
			url = url.replace('http://', '')
			url = url.replace('https://', '')

		context = ssl.create_default_context()
		with socket.create_connection((url, 443)) as sock:
			with context.wrap_socket(sock, server_hostname=url) as ssock:
				dercert = ssock.getpeercert(True)
				cert = ssl.DER_cert_to_PEM_cert(dercert)
				target_x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)

		return target_x509

	@staticmethod
	def custom_x509(x509=None):
		'''
		Values from the input x509 will be transferred to a new x509 and signed by us and returned.

		:param x509: crypto x509 object
		:return: crypto x509 object
		'''

		if not x509:
			raise Exception('Crypto x509', 'Crypto x509 object required')

		spoofed_x509 = crypto.X509()

		subject = x509.get_subject()
		if subject.C:
			spoofed_x509.get_subject().C = subject.C
		if subject.ST:
			spoofed_x509.get_subject().ST = subject.C
		if subject.L:
			spoofed_x509.get_subject().L = subject.C
		if subject.O:
			spoofed_x509.get_subject().O = subject.O
		if subject.OU:
			spoofed_x509.get_subject().OU = subject.OU
		if subject.CN:
			spoofed_x509.get_subject().CN = subject.CN
		if x509.get_serial_number():
			spoofed_x509.set_serial_number(x509.get_serial_number())

		ext = []
		for i in range(0, x509.get_extension_count()):
			ext.append(x509.get_extension(i))

		x509.add_extensions(ext)

		day_in_seconds = 86400
		if x509.get_notBefore():
			# Negative seconds move us back in time by X seconds
			spoofed_x509.set_notBefore(x509.get_notBefore())
		else:
			# Randomly pick an amount of days from 1 to 365, this makes the spoofed_x509 valid from 1 to 365 days ago
			days = random.randint(1, 365)
			spoofed_x509.gmtime_adj_notBefore(days * -day_in_seconds)

		if x509.get_notAfter():
			# Positive seconds move us forward in time by X seconds
			spoofed_x509.set_notAfter(x509.get_notAfter())
		else:
			# Randomly pick an amount of days from 60 to 365, this makes the spoofed_x509 valid for 60 to 365 days
			days = random.randint(60, 365)
			spoofed_x509.gmtime_adj_notAfter(days * day_in_seconds)

		spoofed_x509.set_version(spoofed_x509.get_version())
		spoofed_x509.set_issuer(spoofed_x509.get_subject())
		return spoofed_x509

	@staticmethod
	def generate_cert_and_key(folder_path='./ghost/certs', folder_name=None, cert_name='ghost.crt', key_name='ghost.key', x509=None, bits=4096):
		'''
		Generate self signed certs that will be used to patch any generated payloads and verify any ghost server/client.
		Raises exceptions if no folder_name is provided or the user specifies an invalid value for one of the
		certificate options.

		:param folder_path: The root path you would like to create your cert folders to be stored.
		:param folder_name: The name of the folder that will be stored in folder_path. This will contain your certificates
		:param cert_name: The name and file extension of the certificate you are generating.
		:param key_name: The name and file extension of the private key you are creating.
		:param bits: The public key strength
		:return: os.EX_OK on success
		'''
		if folder_path is './ghost/certs':
			folder_path = os.path.join(os.path.dirname(__file__), "certs")

		if x509 is None:
			raise Exception('x509 required', 'A crypto x509 object is required')

		if folder_name is None or folder_name is '':
			raise Exception('Folder Name', 'An output folder name is required')
		path = os.path.join(folder_path, folder_name)
		try:
			os.makedirs(path)
		except FileExistsError:
			shutil.rmtree(path)
			os.makedirs(path)

		cert_file = os.path.join(path, cert_name)
		key_file = os.path.join(path, key_name)
		key = crypto.PKey()
		key.generate_key(crypto.TYPE_RSA, bits)

		cert = x509
		cert.set_pubkey(key)
		cert.sign(key, 'sha256')

		with open(cert_file, 'wt') as output_cert:
			raw_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8')
			output_cert.writelines(raw_cert)

		with open(key_file, 'wt') as output_key:
			raw_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')
			output_key.writelines(raw_key)

		return os.EX_OK


if __name__ == '__main__':
	for arg in sys.argv:
		if arg == "--version":
			print("TCPGhost client version {0}".format(version))
			sys.exit(os.EX_SOFTWARE)

	parser = argparse.ArgumentParser(epilog=HELP_EPILOG, formatter_class=argparse.RawTextHelpFormatter)
	parser.add_argument('-L', dest='loglvl', action='store', choices=['INFO', 'WARNING', 'ERROR', 'CRITICAL', 'DEBUG'], default='INFO', help='set the logging level')
	parser.add_argument("--lhost", dest="lhost", default="127.0.0.1", help="Host to bind and wait for connections, default 127.0.0.1")
	parser.add_argument("--lport", dest="lport", type=int, default=1080, help="Local port to listen on, default 1080")
	parser.add_argument("--rhost", dest="rhost", required=True, help="Remote host (DNS or IP)")
	parser.add_argument("--rport", dest="rport", required=True, type=int, help="Remote host port")
	parser.add_argument("--cert", dest="cert", default=None, help="Certificate file")
	parser.add_argument("--key", dest="key", default=None, help="Key file")
	parser.add_argument("--spoof", dest="spoof", default=None, help="URL to spoof certs from (steal and self sign)")
	parser.add_argument("--plugin", dest="plugin", help="Name of module located in plugins folder")
	parser.add_argument("--force_verification", dest="force_verification", action='store_true', help="Only allow connection if the target is using a cert signed by our CA")

	options = parser.parse_args()
	logging.getLogger(logging.basicConfig(level=getattr(logging, options.loglvl), format=""))

	if options.cert or options.key:
		certs = [options.cert, options.key]
		for cert in certs:
			if not os.path.isfile(cert):
				logging.error("Cannot load certificates. Verify valid paths were provided.")
				sys.exit(os.EX_SOFTWARE)

	if os.getuid() is not 0:
		logging.info("Try again as root!")
		sys.exit(os.EX_SOFTWARE)

	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	is_bound = False
	while is_bound is False:
		try:
			server_socket.bind((options.lhost, options.lport))
			is_bound = True
		except OSError:
			delay = 5
			logging.error("Cannot bind to port {0} as it's currently in use. Waiting {1} seconds and trying again..".format(options.lport, delay))
			time.sleep(delay)

	if options.plugin:
		try:
			plugin = TCPGhost.load_plugin(options.plugin)
			plugin_worker = threading.Thread(target=plugin.TCPGhostPlugin.plugin_setup,)
			plugin_worker.start()
		except FileNotFoundError:
			sys.exit(os.EX_SOFTWARE)
	else:
		plugin = None

	if options.spoof:
		logging.info("Grabbing cert from {0}".format(options.spoof))
		x509 = TCPGhost.get_target_x509(url=options.spoof)
		if x509:
			logging.info("Success. Outputting certificates into certs folder".format(options.spoof))
		else:
			logging.info("Failure. Something went wrong spoofing the certificate.")
			sys.exit(os.EX_SOFTWARE)
		x509 = TCPGhost.custom_x509(x509=x509)
		TCPGhost.generate_cert_and_key(folder_path='certs', folder_name=options.spoof, x509=x509)
		path = os.path.join('certs', options.spoof)
		options.cert = os.path.join(path, 'ghost.crt')
		options.key = os.path.join(path, 'ghost.key')

	server_socket.listen(5)
	logging.debug("TCPGhost version {0}".format(version))
	logging.info("Waiting for client...")
	threads = []
	while True:
		try:
			client_socket, address = server_socket.accept()

			ghost = TCPGhost(client_socket, options.rhost, options.rport, options.cert, options.key, options.force_verification, plugin)
			worker = threading.Thread(target=ghost.relay_and_cleanup,)
			threads.append(worker)
			ghost.thread = worker
			logging.info("Client connected. Creating: {0}".format(worker.name))
			worker.start()

		except KeyboardInterrupt:
			logging.info("Shutting down...")
			break
		except FileNotFoundError as e:
			logging.info(e)

		except Exception as e:
			logging.debug(e)

	server_socket.close()

