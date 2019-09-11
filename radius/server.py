#!/usr/bin/python

# Copyright (C) 2019 strangebit

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Main configuration
from config import config
config = config.config;

# Internal protocol handling classes
from radius import radius;
from eap import eap;
from tls import tls;

# Utilities
from utils import Utils;

# Cryptographic routines
import crypto;
from crypto import utils;
from crypto import certs;
from Crypto.PublicKey import RSA;
from crypto import rsa;

# Timing
from time import sleep;

# Packet processor
from processor import PacketProcessor

# Threading
import threading;

# Network socket library
import socket

# System library
import sys
import traceback


# Base 16 
from binascii import hexlify
from binascii import unhexlify


#TLS
from tls import tls
tls_state_machine = tls.TLSStateMachine();

# Database
from warehouse import db
database = db.Database(config);

def authentication_loop(socket):
	"""
	Runs the authentication loop. This is the main loop 
	where TLS packets are processed and state is maintained
	"""
	certificate = certs.X509v3Certificate.load(config["security"]["certificate_path"]);
	private_key = certs.RSAPrivateKey.load(config["security"]["private_key"]);
	mtu = config["networking"]["mtu"];
	running = True;
	outstanding_packets = dict();
	handshake_packets = dict();
	duplicates = dict();
	eap_identifier = 1;
	while running:
		data, address = socket.recvfrom(mtu);
		src_ip = address[0];
		src_port = address[1];
		print("Got packet from address %s on port %s" % (src_ip, src_port))
		try:
			radius_packet = radius.RADIUSPacket(data);
			calling_station_id = Utils.Utils.get_calling_station_id(radius_packet);
			"""
			The Identifier field is one octet, and aids in matching requests
			and replies.  The RADIUS server can detect a duplicate request if
			it has the same client source IP address and source UDP port and
			Identifier within a short span of time.
			"""
			if calling_station_id not in duplicates.keys():
				duplicates[calling_station_id] = radius_packet.get_identifier();
			else:
				if duplicates[calling_station_id] == radius_packet.get_identifier():
					print("We have a duplicate. Skipping...");
					continue;
				else:
					duplicates[calling_station_id] = radius_packet.get_identifier();
			print("Packet type: %d" % (radius_packet.get_code()));
			#
			if radius_packet.get_code() == radius.RADIUS_ACCESS_REQUEST_TYPE:
				authenticator = radius_packet.get_authenticator();
				radius_identifier = radius_packet.get_identifier();
				"""
				Check the authenticity of the RADIUS packet
				"""
				if not PacketProcessor.verify_access_request_packet(radius_packet):
					print("RADIUS packet verification failure. Skipping the packet...");
					continue;
				# Construct EAP message from fragments
				fragments = Utils.Utils.get_eap_packet(radius_packet);
				if not calling_station_id:
					print("No calling station ID present in RADIUS packet. Skipping...");
					continue;
				# Non-EAP packet (need to check what to do in case no EAP message is present in RADIUS packet)
				if len(fragments) == 0x0:
					print("No RADIUS encapsulated EAP packet fragments were found. Skipping...");
					continue; # Silently drop the packet for now
				eap_packet = eap.EAPPacket(fragments);
				if eap_packet.get_type() == eap.EAP_IDENTITY_TYPE:
					if tls_state_machine.get_state(calling_station_id):
						print("TLS state already exists. Perhaps this is a duplicate. Skipping.");
						continue;
					print("Sending RADIUS access challenge in response to RADIUS access request...");
					#print("Sending encapsulated EAP Request packet with start flag set to 1...");
					radius_challenge = PacketProcessor.handle_identity_packet(eap_packet, 
						tls_state_machine, 
						calling_station_id,
						authenticator,
						radius_identifier,
						eap_identifier,
						socket,
						address);
					eap_identifier = (eap_identifier + 1) % 0x100;
				elif eap_packet.get_type() == eap.EAP_TTLS_TYPE:
					print("Got EAP TTLS packet");
					# Reconstruct EAP TTLS packet from fragments
					eap_ttls_packet = eap.EAPTTLSPacket(fragments);
					tls_state = tls_state_machine.get_state(calling_station_id);
					if not tls_state:
						print("Invalid TLS state.");
						continue;
					if eap_ttls_packet.get_code() != eap.EAP_TTLS_RESPONSE_CODE:
						print("Should be EAP TTLS response packet. Droping...");
						continue;
					flags = eap_ttls_packet.get_flags();
					has_more_fragments = eap.HAS_MORE_FRAGMENTS(flags);
					# If the packet has more fragments flag set we should 
					# reassemble the TLS packet before we can parse it.
					if not has_more_fragments:
						# If we have not seen client's hello we should process it first
						print("We have received unfragmented packet...");
						if not tls_state.get_client_hello_received():
							handshake_packets[calling_station_id] = [];
							# We are looking for TLS client's hello packet
							tls_packet = tls.TLSPacket(eap_ttls_packet.get_bytes_without_header());
							if tls_packet.get_records()[0].get_content_type() == tls.TLS_CONTENT_TYPE_ALERT:
								print("Error has occured.");
								continue;
							if not (PacketProcessor.handle_client_hello_packet(
								tls_packet, 
								tls_state,
								handshake_packets[calling_station_id]
								)):
								print("Failed to handle client hello packet. Skipping");
								continue;
							outstanding_packets[calling_station_id] = PacketProcessor.process_server_hello_packet(
										tls_state, 
										certificate,
										eap_identifier,
										handshake_packets[calling_station_id]
										);
							packet = outstanding_packets[calling_station_id][0];
							outstanding_packets[calling_station_id] = outstanding_packets[calling_station_id][1:];
							PacketProcessor.send_outstanding_packet(
								packet.get_bytes(), 
								authenticator,
								radius_identifier,
								eap_identifier,
								socket,
								address);
							eap_identifier = (eap_identifier + 1) % 0x100;
						elif not tls_state.get_server_hello_sent():
							# We should now send the server's hello packet
							if len(outstanding_packets[calling_station_id]) > 0:
								packet = outstanding_packets[calling_station_id][0];
								outstanding_packets[calling_station_id] = outstanding_packets[calling_station_id][1:];
								PacketProcessor.send_outstanding_packet(
									packet.get_bytes(), 
									authenticator,
									radius_identifier,
									eap_identifier,
									socket,
									address);
								eap_identifier = (eap_identifier + 1) % 0x100;
								if len(outstanding_packets[calling_station_id]) == 0:
									print("Server hello, certificate and server hello done packets have been sent out.");
									tls_state.set_server_hello_sent(True);
									tls_state.set_server_certificate_sent(True);
									tls_state.set_server_hello_done_sent(True);
							else:
								print("We should have outstanding packets. Error...");
								continue;
						elif not tls_state.get_server_certificate_sent():
							# We should now send the server's certificate
							print("We should never be in this state.");
							pass
						elif not tls_state.get_server_hello_done_sent():
							# We should now send the server's hello done
							print("We should never be in this state.");
							pass
						elif not tls_state.get_client_key_exchange_received():
							# We are expecting the client's key exchange protocol
							outstanding_packets[calling_station_id] += eap_ttls_packet.get_bytes_without_header();
							tls_packet = tls.TLSPacket(outstanding_packets[calling_station_id]);
							if tls_packet.get_records()[0].get_content_type() == tls.TLS_CONTENT_TYPE_ALERT:
								print("Error has occured.");
								continue;
							PacketProcessor.handle_client_key_exchange_packet(
								tls_packet,
								tls_state,
								private_key.get_key_info(),
								handshake_packets[calling_station_id]);
							if not PacketProcessor.handle_client_cipher_spec_change_packet(tls_packet, tls_state):
								# This is an error - client's cipher spec change packet must follow the client 
								# key exchange packet
								continue;
							# Verify the encrypted finished message
							if not PacketProcessor.handle_client_encrypted_finish_message(
								tls_packet,
								tls_state, 
								handshake_packets[calling_station_id]):
								print("Failed to verify the encrypted finish message.");
							else:
								print("Verification succeeded.");	
								#print(hexlify(bytearray(PacketProcessor.get_unencrypted_finished_message(tls_state, tls_packet))))
								handshake_packets[calling_station_id] += PacketProcessor.get_unencrypted_finished_message(tls_state, tls_packet);
								#tls_state.set_client_finished_message_received(True);
								PacketProcessor.process_server_cipher_spec_changed_packet(
									authenticator, 
									radius_identifier,
									eap_identifier,
									socket,
									address);
								eap_identifier = (eap_identifier + 1) % 0x100;
								tls_state.set_client_key_exchange_received(True);
								#tls_state.set_server_cipher_spec_changed_sent(True);
						elif not tls_state.get_server_cipher_spec_changed_sent():
							print("Processing server's encrypted message.");
							PacketProcessor.process_server_encrypted_finish_message(
									tls_state, 
									handshake_packets[calling_station_id],
									authenticator,
									radius_identifier,
									socket,
									address
									);
							tls_state.set_server_cipher_spec_changed_sent(True);
							tls_state.set_server_finished_message_sent(True);
							continue;
						elif tls_state.get_server_finished_message_sent():
							tls_packet = tls.TLSPacket(eap_ttls_packet.get_bytes_without_header());
							if tls_packet.get_records()[0].get_content_type() == tls.TLS_CONTENT_TYPE_ALERT:
								print("Encrypted alert. Skipping.");
								PacketProcessor.process_encrypted_alert(tls_state, tls_packet);
								continue;
							elif tls_packet.get_records()[0].get_content_type() == tls.TLS_CONTENT_TYPE_APPLICATION_DATA:
								print("Expecting PAP packet with AVPs (username and password)");
								attributes = PacketProcessor.process_encrypted_pap_avp(tls_state, tls_packet);
								username = None;
								password = None;
								for attribute in attributes:
									if attribute.get_code() == eap.PAP_USERNAME_ATTRIBUTE_CODE:
										username = utils.Utils.remove_null_bytes(attribute.get_data());
									elif attribute.get_code() == eap.PAP_PASSWORD_ATTRBIUTE_CODE:
										password = utils.Utils.remove_null_bytes(attribute.get_data());
									else:
										print("Unknown attribute");
										continue;
								if database.authenticate(username, password):
									print("Access was granted to the user");
									(bytes_remaining, conn_speed) = database.get_bytes_remaining_and_conn_speed(username);
									PacketProcessor.handle_access_accept(
										tls_state, 
										bytes_remaining,
										conn_speed,
										authenticator, 
										radius_identifier,
										socket,
										address);
								else:
									print("Access was rejected");
									PacketProcessor.handle_access_reject(
										authenticator, 
										radius_identifier,
										socket,
										address);
						else:
							print("Unknonw state. We should never be here.")
					else:
						if not tls_state.get_client_hello_received():
							# We are looking for TLS client's hello packet
							pass
						elif not tls_state.get_server_hello_sent():
							# We should now send the server's hello packet
							pass
						elif not tls_state.get_server_certificate_sent():
							# We should now send the server's certificate
							pass
						elif not tls_state.get_server_hello_done_sent():
							# We should now send the server's hello done
							pass
						elif not tls_state.get_client_key_exchange_received():
							# We are expecting the client's key exchange protocol
							outstanding_packets[calling_station_id] += eap_ttls_packet.get_bytes_without_header();
							PacketProcessor.acknowledge_client_key_exchange_fragment(
								authenticator,
								radius_identifier,
								eap_identifier,
								socket,
								address);
							# This should be done on per client bases
							eap_identifier = (eap_identifier + 1) % 0x100;
						elif not tls_state.get_client_cipher_spec_changed_received():
							# We are expecting the client's cipher spec changed
							pass
						elif not tls_state.get_client_finished_message_received():
							# We are expecting the client's finished message 
							pass
						elif not tls_state.get_server_cipher_spec_changed_sent():
							# We should now
							pass
				else:
					print("Unsupported EAP packet type...");
			else:
				print("Invalid RADIUS packet type recieved. Expected RADIUS Access-Request packet.");
		except Exception as e:
					traceback.print_exc();

def accounting_loop(socket):
	"""
	Runs accounting loop
	"""
	mtu = config["networking"]["mtu"];
	running = True;
	while running:
		data, address = socket.recvfrom(mtu);
		src_ip = address[0];
		src_port = address[1];
		print("Got packet from address %s on port %s" % (src_ip, src_port))
		"""
		RFC 2866 defines attributes which can be used in RADIUS accouting packets
		https://tools.ietf.org/html/rfc2866
		"""
		try:
			radius_packet = radius.RADIUSPacket(data);
			print("Packet type: %s" % (radius_packet.get_code()))
			if radius_packet.get_code() == radius.RADIUS_ACCOUNTING_REQUEST_TYPE:
				print("Got accouting request packet");
				authenticator = radius_packet.get_authenticator();
				radius_identifier = radius_packet.get_identifier();
				"""
				The following steps should be taken:
				(i) verify the authenticity of the packet
				(ii) check the packet's Acct-Status-Type
				(iii) if accouting type is of type Start insert a record into the database
				(iv) if accouting type is of type stop finilize the accounting
				"""
				if not Utils.Utils.verify_accounting_authenticator(radius_packet, bytearray(config["security"]["radius_master_secret"], encoding='utf8')):
					print("Invalid authenticator in RADIUS packet...");
					continue;
				
				PacketProcessor.handle_accounting_response(authenticator, radius_identifier, socket, address);
				continue;
		except Exception as e:
			traceback.print_exc();

"""
Initialize the sockets
"""

"""
Authentication server socket
"""

auth_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
auth_server_address = (config["networking"]["ip"], config["networking"]["radius_auth_port"]);
auth_sock.bind(auth_server_address);

"""
Accounting server socket
"""

acct_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
acct_server_address = (config["networking"]["ip"], config["networking"]["radius_acct_port"]);
acct_sock.bind(acct_server_address);

threading.Thread(target=authentication_loop, args=(auth_sock,)).start();
threading.Thread(target=accounting_loop, args=(acct_sock,)).start();

"""
Maintenance loop
"""


running = True;
maintenance_interval_in_seconds = 2;

from time import time;

while running:
	for tls_state in tls_state_machine.get_states():
		if not tls_state:
			continue;
		if int(time()) - tls_state.get_last_tx_rx_time() > tls.TLS_SESSION_TIMEOUT:
			print("Removing the state ", tls_state.get_calling_station_id());
			tls_state_machine.remove_state(tls_state.get_calling_station_id());
		pass
	sleep(maintenance_interval_in_seconds);
