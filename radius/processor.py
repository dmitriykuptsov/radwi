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

# Import configuration
from config import config;
config = config.config;

# Import utilities
from utils import Utils;

# Import protocols
from radius import radius;
from eap import eap;
from tls import tls;

# Import cryptographic classes
from Crypto.PublicKey import RSA;

import crypto;
from crypto import utils;
from crypto import certs;
from crypto import rsa;
from crypto import aes;
from crypto import wpa2;

# 
from binascii import hexlify
from binascii import unhexlify

# Structs
import struct

class PacketProcessor():
	"""
	Helper class for packet handling
	"""
	@staticmethod
	def verify_access_request_packet(
		radius_packet):
		"""
		Check the authenticity of the RADIUS packet
		"""
		if not (Utils.Utils.verify_message_authentication(
			radius_packet, 
			bytearray(config["security"]["radius_master_secret"], encoding='utf8'))):
			print("Got packet with invalid authentication message. Skipping the packet...");
			return False;
		return True;
	@staticmethod
	def handle_identity_packet(
		eap_packet, 
		tls_state_machine, 
		calling_station_id,
		authenticator,
		radius_identifier,
		eap_identifier,
		socket,
		address):
		"""
		Handles identity packet
		"""
		user_identity = eap_packet.get_bytes_without_header();
		print("Got EAP Identity: %s" % ("".join(map(chr, user_identity))));
		"""
		Create EAP TTLS request packet
		"""
		eap_start = eap.EAPTTLSRequest();
		eap_start.set_is_start_flag();
		eap_start.set_identifier(eap_identifier);
		# Fix me we need to handle identifiers
		#eap_start.set_identifier(eap_identifier);
		#eap_identifier += 1;

		eap_start_bytes = eap_start.get_bytes();

		radius_challenge = radius.RADIUSPacket();
		"""
		Set the code of the RADIUS packet to challenge type
		"""
		radius_challenge.set_code(radius.RADIUS_ACCESS_CHALLENGE_TYPE);
		"""
		Set correct value of the authenticator field
		"""
		radius_challenge.set_authenticator(authenticator);
		"""
		Set the identifier so that the NAS can match request with response
		"""
		radius_challenge.set_identifier(radius_identifier);
		eap_attribute = (
			radius.RADIUSAttribute(
				radius.RADIUS_EAP_MESSAGE_ATTRIBUTE, 
				eap_start_bytes));
		radius_challenge.add_attribute(eap_attribute);
		message_authenticator_attribute = (
			radius.RADIUSAttribute(
				radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE, 
				[0] * radius.RADIUS_AUTHENTICATOR_FIELD_LENGTH));
		radius_challenge.add_attribute(message_authenticator_attribute);
		"""
		Compute message authentication
		"""
		message_authentication_bytes = (
			Utils.Utils.compute_message_authentication(radius_challenge, 
				bytearray(config["security"]["radius_master_secret"], encoding='utf8')));
		"""
		Update the message authentication attribute
		"""
		radius_challenge = Utils.Utils.set_message_authentication(
			radius_challenge, message_authentication_bytes);
		"""
		Compute and update response authenticator
		"""
		response_authenticator = Utils.Utils.compute_response_authenticator(radius_challenge,
			bytearray(config["security"]["radius_master_secret"], encoding='utf8'));
		radius_challenge.set_authenticator(response_authenticator);
		"""
		Initialize state
		"""
		tls_state_machine.init_state(calling_station_id);
		"""
		Send response packet 
		"""
		bytes_out = socket.sendto(bytearray(radius_challenge.get_bytes()), address);
		print("Sent %d" % (bytes_out));

	@staticmethod
	def handle_client_hello_packet(
		tls_packet,
		tls_state,
		handshake_packets):
		"""
		Processes client's hello packet
		"""
		tls_records = tls_packet.get_records();
		if len(tls_records) != 0x1:
			print("Number of protocols is not equal to one. Skipping")
			# Handle error
			# We need to throw exception here
			return False;
		protocols = tls_records[0].get_handshake_protocols(tls_state);
		if not len(protocols) == 0x1:
			print("Number of records is grater than 1. Skipping");
			# Send alert to the client
			# We need to throw exception here
			return False;
		client_hello_protocol = protocols[0];
		if not isinstance(client_hello_protocol, tls.TLSClientHelloProtocol):
			print("Must be client hello handshake protocol");
			# We need to throw exception here
			return False;
		if client_hello_protocol.get_version() != tls.TLS_PROTOCOL_VERSION:
			print("Version not supported");
			return False;
		client_random = client_hello_protocol.get_random();
		tls_state.set_client_random(client_random);
		cipher_suits = client_hello_protocol.get_cipher_suits();
		compression_methods = client_hello_protocol.get_compressions();
		handshake_packets += client_hello_protocol.get_bytes();
		tls_state.set_client_hello_received(True);
		return True
	@staticmethod
	def process_server_hello_packet(
		tls_state,
		certificate,
		eap_identifier,
		handshake_packets):
		#Processes server's hello packet
		tls_record_layer = tls.TLSRecordLayer();
		server_hello_protocol = tls.TLSServerHelloProtocol();

		#Generate server side random number
		server_random = crypto.utils.Utils.generate_random(tls.HANDSHAKE_SERVER_HELLO_RANDOM_LENGTH);
		
		#Update server side random number in TLS state
		tls_state.set_server_random(server_random);
		
		#Set server side random number in server hello protocol
		server_hello_protocol.set_random(server_random);
		handshake_packets += server_hello_protocol.get_bytes();
		tls_record_layer.add_handshake_protocol(server_hello_protocol);
		
		#Add server certificate
		server_certificate_protocol = tls.TLSCertificateProtocol();
		server_certificate_protocol.add_certificate(certificate);
		tls_record_layer.add_handshake_protocol(server_certificate_protocol);
		handshake_packets += server_certificate_protocol.get_bytes();

		server_hello_done_protocol = tls.TLSSeverHelloDoneProtocol();
		tls_record_layer.add_handshake_protocol(server_hello_done_protocol);
		handshake_packets += server_hello_done_protocol.get_bytes();

		tls_packet = tls.TLSPacket();
		tls_packet.add_record(tls_record_layer);
		tls_packet_bytes = tls_packet.get_bytes();
		total_length = len(tls_packet_bytes);

		outstanding_packets = [];
		offset = 0;
		max_eap_packet_size = config["networking"]["max_eap_packet_size"];
		has_more_eap_ttls_fragments = True;
		is_first_fragment = True;
		while has_more_eap_ttls_fragments:
			eap_ttls_packet = eap.EAPTTLSRequest();
			eap_ttls_packet.set_identifier(eap_identifier);
			eap_identifier += 1;
			if offset + max_eap_packet_size < len(tls_packet_bytes):
				eap_ttls_packet.set_has_more_fragments_flag();
				if is_first_fragment:
					eap_ttls_packet.set_length_included_flag();
					is_first_fragment = False;
				eap_ttls_packet.set_payload(tls_packet_bytes[offset:offset+max_eap_packet_size], total_length);
				outstanding_packets.append(eap_ttls_packet);
				offset = offset + max_eap_packet_size
			else:
				eap_ttls_packet.set_payload(tls_packet_bytes[offset:len(tls_packet_bytes)], total_length);
				outstanding_packets.append(eap_ttls_packet);
				has_more_eap_ttls_fragments = False;
		return outstanding_packets;
	@staticmethod
	def send_outstanding_packet(
		eap_packet, 
		authenticator, 
		radius_identifier,
		eap_identifier,
		socket,
		address):
		radius_challenge = radius.RADIUSPacket();
		"""
		Set the code of the RADIUS packet to challenge type
		"""
		radius_challenge.set_code(radius.RADIUS_ACCESS_CHALLENGE_TYPE);
		"""
		Set correct value of the authenticator field
		"""
		radius_challenge.set_authenticator(authenticator);
		"""
		Set the identifier so that the NAS can match request with response
		"""
		radius_challenge.set_identifier(radius_identifier);
		#message = outstanding_packets[calling_station_id][0].get_bytes();
		Utils.Utils.radius_split_message(
			radius_challenge, 
			eap_packet, 
			config["networking"]["eap_message_attribute_length"]
			);
		message_authenticator_attribute = (
			radius.RADIUSAttribute(
				radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE, 
				[0] * radius.RADIUS_AUTHENTICATOR_FIELD_LENGTH));
		radius_challenge.add_attribute(message_authenticator_attribute);
		"""
		Compute message authentication
		"""
		message_authentication_bytes = (
			Utils.Utils.compute_message_authentication(radius_challenge, 
				bytearray(config["security"]["radius_master_secret"], encoding='utf8')));
		"""
		Update the message authentication attribute
		"""
		radius_challenge = Utils.Utils.set_message_authentication(
			radius_challenge, 
			message_authentication_bytes);
		"""
		Compute and update response authenticator
		"""
		response_authenticator = Utils.Utils.compute_response_authenticator(radius_challenge,
			bytearray(config["security"]["radius_master_secret"], encoding='utf8'));
		radius_challenge.set_authenticator(response_authenticator);
		bytes_out = socket.sendto(bytearray(radius_challenge.get_bytes()), address);
		print("Sent %d" % (bytes_out));
	@staticmethod
	def process_server_cipher_spec_changed_packet(
		authenticator, 
		radius_identifier,
		eap_identifier,
		socket,
		address):

		tls_record_layer = tls.TLSRecordLayer();
		tls_record_layer.set_content_type(tls.TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC);
		tls_record_layer.set_message([tls.TLS_CHANGE_CIPHER_SPEC_MESSAGE]);
		
		tls_packet = tls.TLSPacket();
		tls_packet.add_record(tls_record_layer);

		radius_challenge = radius.RADIUSPacket();
		"""
		Set the code of the RADIUS packet to challenge type
		"""
		radius_challenge.set_code(radius.RADIUS_ACCESS_CHALLENGE_TYPE);
		"""
		Set correct value of the authenticator field
		"""
		radius_challenge.set_authenticator(authenticator);
		"""
		Set the identifier so that the NAS can match request with response
		"""
		radius_challenge.set_identifier(radius_identifier);

		tls_packet_bytes = tls_packet.get_bytes();

		eap_ttls_packet = eap.EAPTTLSRequest();

		eap_ttls_packet.set_identifier(eap_identifier);
			
		eap_ttls_packet.set_payload(tls_packet_bytes, len(tls_packet_bytes));
		
		#message = outstanding_packets[calling_station_id][0].get_bytes();
		Utils.Utils.radius_split_message(
			radius_challenge, 
			eap_ttls_packet.get_bytes(), 
			config["networking"]["eap_message_attribute_length"]
			);
		message_authenticator_attribute = (
			radius.RADIUSAttribute(
				radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE, 
				[0] * radius.RADIUS_AUTHENTICATOR_FIELD_LENGTH));
		radius_challenge.add_attribute(message_authenticator_attribute);
		"""
		Compute message authentication
		"""
		message_authentication_bytes = (
			Utils.Utils.compute_message_authentication(radius_challenge, 
				bytearray(config["security"]["radius_master_secret"], encoding='utf8')));
		"""
		Update the message authentication attribute
		"""
		radius_challenge = Utils.Utils.set_message_authentication(
			radius_challenge, 
			message_authentication_bytes);
		"""
		Compute and update response authenticator
		"""
		response_authenticator = Utils.Utils.compute_response_authenticator(radius_challenge,
			bytearray(config["security"]["radius_master_secret"], encoding='utf8'));
		radius_challenge.set_authenticator(response_authenticator);
		bytes_out = socket.sendto(bytearray(radius_challenge.get_bytes()), address);
		print("Sent %d" % (bytes_out));
	@staticmethod
	def process_server_certificate_packet():
		"""
		Processes server's certificate packet
		"""
		pass
	@staticmethod
	def process_server_hello_done_packet():
		"""
		Processes server's hello done packet
		"""
		pass
	@staticmethod
	def handle_client_key_exchange_packet(
		tls_packet, 
		tls_state,
		key,
		handshake_packets
		):
		#private_key.get_key_info()
		"""
		Handles client's key exchange packet
		"""
		print("We have recieved TLS packet which was not fragmented.");
		#for record in records:
		"""
		We should expect two records: (i) cipher spec changed (ii) encrypted message
		"""
		records = tls_packet.get_records();
		client_key_exchange_protocol = records[0].get_handshake_protocols(tls_state)[0];
		if not isinstance(client_key_exchange_protocol, tls.TLSClientKeyExchangeProtocol):
			print("We are expecting TLS client key exchage protocol. Skipping");
			# We need to throw exception here
			return False;
		handshake_packets += client_key_exchange_protocol.get_bytes();
		"""
		Decrypt pre master secret
		"""
		encrypted_pre_master_secret = client_key_exchange_protocol.get_encrypted_premaster_secret();
		#pre_master_secret = rsa.RSACrypto().decrypt(bytearray(encrypted_pre_master_secret), key);
		pre_master_secret = utils.Utils.derive_pre_master_secret(
			bytearray(encrypted_pre_master_secret), 
			tls.TLS_PROTOCOL_VERSION, 
			key);
		"""
		Derive keying materail for the TLS session
		"""
		
		#pre_master_secret = rsa.RSACrypto().decrypt(bytearray(encrypted_pre_master_secret), key);
		"""
		Compute master secret
		"""
		master_secret = utils.Utils.compute_master_secret(
			pre_master_secret, 
			bytearray(tls_state.get_client_random()),
			bytearray(tls_state.get_server_random()));
		keying_material = utils.Utils.compute_keying_material(
			master_secret, 
			bytearray(tls_state.get_client_random()),
			bytearray(tls_state.get_server_random()));
		"""
		Derive session keys
		"""
		client_mac_key = utils.Utils.generate_client_write_mac_key(keying_material);
		server_mac_key = utils.Utils.generate_server_write_mac_key(keying_material);
		client_cipher_key = utils.Utils.generate_client_write_cipher_key(keying_material);
		server_cipher_key = utils.Utils.generate_server_write_cipher_key(keying_material);
		client_iv = utils.Utils.generate_client_write_iv(keying_material);
		server_iv = utils.Utils.generate_server_write_iv(keying_material);
		"""
		Update TLS state with newly computed keying material
		"""
		tls_state.set_master_secret(master_secret);
		tls_state.set_client_write_mac_key(client_mac_key);
		tls_state.set_client_write_iv(client_iv);
		tls_state.set_client_write_cipher_key(client_cipher_key);
		tls_state.set_server_write_cipher_key(server_cipher_key);
		tls_state.set_server_write_mac_key(server_mac_key);
		tls_state.set_server_write_iv(server_iv);
	@staticmethod
	def handle_client_cipher_spec_change_packet(
		tls_packet,
		tls_state
		):
		"""
		Handles client's cipher spec change packet
		"""
		records = tls_packet.get_records();
		for record in records:
			if tls.TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC != record.get_content_type():
				print("We have reached encrypted state...");
				tls_state.set_client_cipher_spec_changed_received(True);
				return True;
		print("We are expecting TLS cipher spec change protocol. Found none. Skipping.");
		return False;
	@staticmethod
	def get_unencrypted_finished_message(tls_state, tls_packet):
		"""
		Extracts finished message from TLS packet
		"""
		records = tls_packet.get_records();
		encrypted_finished_protocol = bytearray(records[2].get_bytes_without_header());
		key = tls_state.get_client_write_cipher_key();
		iv = encrypted_finished_protocol[0:aes.IV_SIZE];
		cipher = aes.AESCipher(aes.AES_CBC_MODE, key, iv);
		decrypted_bytes = cipher.decrypt(encrypted_finished_protocol[aes.IV_SIZE:len(encrypted_finished_protocol)]);
		length = ((decrypted_bytes[tls.TLS_HANDSHAKE_LENGTH_OFFSET] << 16) |
			(decrypted_bytes[tls.TLS_HANDSHAKE_LENGTH_OFFSET + 1] << 8) |
			(decrypted_bytes[tls.TLS_HANDSHAKE_LENGTH_OFFSET + 2] & 0xFF));
		finished_message_protocol = tls.FinishedMessageProtocol(decrypted_bytes[0:tls.FINISHED_MESSAGE_VERIFY_DATA_OFFSET + length]);
		#hexlify(bytearray(finished_message_protocol.get_bytes()))
		return finished_message_protocol.get_bytes();
	@staticmethod
	def handle_client_encrypted_finish_message(tls_packet, tls_state, handshake_messages):
		"""
		Handles client's encrypted finished message
		"""
		# We need to check the number of records first. It can be that all protocols are 
		# embedded into single record layer.
		records = tls_packet.get_records();
		# This ugly code needs to be restructured
		# Also we should consider TLS packets which have single record, but many protocols
		encrypted_finished_protocol = bytearray(records[2].get_bytes_without_header());
		key = tls_state.get_client_write_cipher_key();
		iv = encrypted_finished_protocol[0:aes.IV_SIZE];
		cipher = aes.AESCipher(aes.AES_CBC_MODE, key, iv);
		decrypted_bytes = cipher.decrypt(encrypted_finished_protocol[aes.IV_SIZE:len(encrypted_finished_protocol)]);
		master_secret = tls_state.get_master_secret();
		finished_message_protocol = tls.FinishedMessageProtocol(decrypted_bytes);
		verify_data_original = finished_message_protocol.get_verify_data();
		# https://stackoverflow.com/questions/2359662a2/tls-1-0-calculating-the-finished-message-mac
		# https://tools.ietf.org/html/rfc5246#section-6.2.3.1
		length = finished_message_protocol.get_length();
		offset = tls.FINISHED_MESSAGE_VERIFY_DATA_OFFSET + length;
		hmac_value = decrypted_bytes[offset:offset + tls.FINISHED_MESSAGE_HMAC_LENGTH];
		#print(hexlify(bytearray(hmac_value)));
		message = decrypted_bytes[0:tls.FINISHED_MESSAGE_VERIFY_DATA_OFFSET + length];
		client_sequence_number = tls_state.get_client_sequence_number();
		if not (utils.Utils.verify_mac(
			tls_state.get_client_write_mac_key(), 
			client_sequence_number,
			tls.TLS_CONTENT_TYPE_HANDSHAKE,
			tls.TLS_PROTOCOL_VERSION,
			message,
			hmac_value
			)):
			print("Failed to verify MAC of the finished message. Dropping...");
			return False;
		tls_state.increment_client_sequence_number();
		verify_data_computed = utils.Utils.verify_client_finshed_message(
			master_secret, 
			handshake_messages, 
			finished_message_protocol.get_length());
		return utils.Utils.compare_bytearrays(verify_data_original, verify_data_computed);
	@staticmethod
	def process_server_cipher_spec_change_message():
		"""
		Processes server's cipher spec change message
		"""
		pass
	@staticmethod
	def process_server_encrypted_finish_message(
		tls_state, 
		handshake_messages, 
		authenticator,
		radius_identifier,
		socket, 
		address):
		"""
		Processes server's encrypted finish message
		"""
		master_secret = tls_state.get_master_secret();

		verify_data_computed = utils.Utils.verify_server_finshed_message(
			master_secret, 
			handshake_messages, 
			tls.FINISHED_MESSAGE_VERIFY_DATA_LENGTH);

		server_sequence_number = tls_state.get_server_sequence_number();

		tls_packet = tls.TLSPacket();
		tls_record = tls.TLSRecordLayer();

		finished_message_protocol = tls.FinishedMessageProtocol();
		finished_message_protocol.set_verify_data(verify_data_computed);

		hmac = utils.Utils.compute_server_finished_message_mac(
			tls_state.get_server_write_mac_key(), 
			server_sequence_number,
			tls.TLS_CONTENT_TYPE_HANDSHAKE,
			tls.TLS_PROTOCOL_VERSION,
			finished_message_protocol.get_bytes()
			);

		finished_message_protocol_bytes = finished_message_protocol.get_bytes();

		message = bytearray(finished_message_protocol_bytes) + hmac;

		# This should be 
		# padding = [(aes.BLOCK_SIZE - len(message) % aes.BLOCK_SIZE)] * (aes.BLOCK_SIZE - len(message) % aes.BLOCK_SIZE);
		padding = [0x0f] * (aes.BLOCK_SIZE - len(message) % aes.BLOCK_SIZE);
		padding[len(padding) - 1] = len(padding) - 1;

		key = tls_state.get_server_write_cipher_key();
		iv = utils.Utils.generate_random(aes.IV_SIZE);		
		cipher = aes.AESCipher(aes.AES_CBC_MODE, key, iv);
		encrypted_bytes = cipher.encrypt((message + bytearray(padding)));

		tls_record.add_encrypted_protocol(bytearray(iv + encrypted_bytes));
		tls_packet.add_record(tls_record);

		eap_ttls_packet = eap.EAPTTLSRequest();
		eap_ttls_packet.set_payload(tls_packet.get_bytes(), len(tls_packet.get_bytes()));
		packet = eap_ttls_packet.get_bytes();
		radius_challenge = radius.RADIUSPacket();
		"""
		Set the code of the RADIUS packet to challenge type
		"""
		radius_challenge.set_code(radius.RADIUS_ACCESS_CHALLENGE_TYPE);
		"""
		Set correct value of the authenticator field
		"""
		radius_challenge.set_authenticator(authenticator);
		"""
		Set the identifier so that the NAS can match request with response
		"""
		radius_challenge.set_identifier(radius_identifier);
		#message = outstanding_packets[calling_station_id][0].get_bytes();
		Utils.Utils.radius_split_message(radius_challenge, 
			packet, 
			config["networking"]["eap_message_attribute_length"]);
		message_authenticator_attribute = (
			radius.RADIUSAttribute(
				radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE, 
				[0] * radius.RADIUS_AUTHENTICATOR_FIELD_LENGTH));
		radius_challenge.add_attribute(message_authenticator_attribute);
		"""
		Compute message authentication
		"""
		message_authentication_bytes = (
			Utils.Utils.compute_message_authentication(radius_challenge, 
				bytearray(config["security"]["radius_master_secret"], encoding='utf8')));
		"""
		Update the message authentication attribute
		"""
		radius_challenge = Utils.Utils.set_message_authentication(radius_challenge, message_authentication_bytes);
		"""
		Compute and update response authenticator
		"""
		response_authenticator = Utils.Utils.compute_response_authenticator(radius_challenge,
			bytearray(config["security"]["radius_master_secret"], encoding='utf8'));
		radius_challenge.set_authenticator(response_authenticator);
		bytes_out = socket.sendto(bytearray(radius_challenge.get_bytes()), address);
		print("Sent %d" % (bytes_out));
		
	@staticmethod
	def acknowledge_client_key_exchange_fragment(
		authenticator,
		radius_identifier,
		eap_identifier,
		socket,
		address
		):

		eap_ttls_packet = eap.EAPTTLSRequest();
		eap_ttls_packet.set_identifier(eap_identifier);
		packet = eap_ttls_packet.get_bytes();
		radius_challenge = radius.RADIUSPacket();
		"""
		Set the code of the RADIUS packet to challenge type
		"""
		radius_challenge.set_code(radius.RADIUS_ACCESS_CHALLENGE_TYPE);
		"""
		Set correct value of the authenticator field
		"""
		radius_challenge.set_authenticator(authenticator);
		"""
		Set the identifier so that the NAS can match request with response
		"""
		radius_challenge.set_identifier(radius_identifier);
		#message = outstanding_packets[calling_station_id][0].get_bytes();
		Utils.Utils.radius_split_message(radius_challenge, 
			packet, 
			config["networking"]["eap_message_attribute_length"]);
		message_authenticator_attribute = (
			radius.RADIUSAttribute(
				radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE, 
				[0] * radius.RADIUS_AUTHENTICATOR_FIELD_LENGTH));
		radius_challenge.add_attribute(message_authenticator_attribute);
		"""
		Compute message authentication
		"""
		message_authentication_bytes = (
			Utils.Utils.compute_message_authentication(radius_challenge, 
				bytearray(config["security"]["radius_master_secret"], encoding='utf8')));
		"""
		Update the message authentication attribute
		"""
		radius_challenge = Utils.Utils.set_message_authentication(radius_challenge, message_authentication_bytes);
		"""
		Compute and update response authenticator
		"""
		response_authenticator = Utils.Utils.compute_response_authenticator(radius_challenge,
			bytearray(config["security"]["radius_master_secret"], encoding='utf8'));
		radius_challenge.set_authenticator(response_authenticator);
		bytes_out = socket.sendto(bytearray(radius_challenge.get_bytes()), address);
		print("Sent %d" % (bytes_out));
	@staticmethod
	def process_encrypted_pap_avp(tls_state, tls_packet):
		records = tls_packet.get_records();
		if len(records) != 0x1:
			return [];
		message = bytearray(records[0].get_bytes_without_header());
		key = tls_state.get_client_write_cipher_key();
		iv = message[0:aes.IV_SIZE];
		cipher = aes.AESCipher(aes.AES_CBC_MODE, key, iv);
		decrypted_bytes = cipher.decrypt(message[aes.IV_SIZE:len(message)]);
		# The decrypted message comprises the following parts:
		# (i) Actual payload
		# (ii) HMAC
		# (iii) Padding
		# (iv) Padding length (last byte)
		payload = decrypted_bytes[0:len(decrypted_bytes) - tls.HMAC_LENGTH - decrypted_bytes[len(decrypted_bytes) - 1] - 1];
		hmac_value = decrypted_bytes[len(payload):len(payload) + tls.HMAC_LENGTH];
		client_sequence_number = tls_state.get_client_sequence_number();
		if not (utils.Utils.verify_mac(
			tls_state.get_client_write_mac_key(), 
			client_sequence_number,
			tls.TLS_CONTENT_TYPE_APPLICATION_DATA,
			tls.TLS_PROTOCOL_VERSION,
			payload,
			hmac_value
			)):
			print("Failed to verify MAC of the PAP message. Dropping...");
			return False;
		tls_state.increment_client_sequence_number();
		return eap.ParseAVP().parse(payload);
	@staticmethod
	def handle_access_reject(authenticator, radius_identifier, socket, address):
		eap_packet = eap.EAPFailure();
		packet = eap_packet.get_bytes();
		radius_reject = radius.RADIUSPacket();
		radius_reject.set_code(radius.RADIUS_ACCESS_REJECT_TYPE);
		radius_reject.set_authenticator(authenticator);
		radius_reject.set_identifier(radius_identifier);
		Utils.Utils.radius_split_message(radius_reject, 
			packet, 
			config["networking"]["eap_message_attribute_length"]);
		message_authenticator_attribute = (
			radius.RADIUSAttribute(
				radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE, 
				[0] * radius.RADIUS_AUTHENTICATOR_FIELD_LENGTH));
		radius_reject.add_attribute(message_authenticator_attribute);
		message_authentication_bytes = (
			Utils.Utils.compute_message_authentication(radius_reject, 
				bytearray(config["security"]["radius_master_secret"], encoding='utf8')));
		radius_reject = Utils.Utils.set_message_authentication(radius_reject, message_authentication_bytes);
		response_authenticator = Utils.Utils.compute_response_authenticator(radius_reject,
			bytearray(config["security"]["radius_master_secret"], encoding='utf8'));
		radius_reject.set_authenticator(response_authenticator);
		bytes_out = socket.sendto(bytearray(radius_reject.get_bytes()), address);
		print("Sent %d" % (bytes_out));
	@staticmethod
	def handle_access_accept(
			tls_state, 
			bytes_remaining, 
			conn_speed, 
			authenticator, 
			radius_identifier, 
			socket, 
			address):
		eap_packet = eap.EAPSuccess();
		packet = eap_packet.get_bytes();
		radius_success = radius.RADIUSPacket();
		radius_success.set_code(radius.RADIUS_ACCESS_ACCEPT_TYPE);
		radius_success.set_authenticator(authenticator);
		radius_success.set_identifier(radius_identifier);
		Utils.Utils.radius_split_message(radius_success, 
			packet, 
			config["networking"]["eap_message_attribute_length"]);
		keying_material = wpa2.WPA2.generate_keying_material(
			tls_state.get_master_secret(), 
			bytearray(tls_state.get_client_random()),
			bytearray(tls_state.get_server_random()));
		# This code was tested and the MSK and EMSK were derived correctly...
		msk_key = wpa2.WPA2.generate_msk(keying_material);
		emsk_key = wpa2.WPA2.generate_emsk(keying_material);

		microsoft_recv_key_attribute = radius.MicrosoftAttribute();
		microsoft_recv_key_attribute.set_value(
			wpa2.WPA2.encrypt_ms_key(
				bytearray(config["security"]["radius_master_secret"], encoding='utf8'), 
				authenticator,
				msk_key[0:wpa2.RECV_KEY_LENGTH]));
		microsoft_recv_key_attribute.set_type(radius.MS_MPPE_RECV_KEY);

		microsoft_send_key_attribute = radius.MicrosoftAttribute();
		microsoft_send_key_attribute.set_value(
			wpa2.WPA2.encrypt_ms_key(
				bytearray(config["security"]["radius_master_secret"], encoding='utf8'), 
				authenticator,
				msk_key[wpa2.RECV_KEY_LENGTH:wpa2.RECV_KEY_LENGTH + wpa2.SEND_KEY_LENGTH]));
		microsoft_send_key_attribute.set_type(radius.MS_MPPE_SEND_KEY);

		mikrotik_conn_speed_attribute = radius.MikroTikAttribute();
		mikrotik_conn_speed_attribute.set_value(bytearray(conn_speed.encode("ascii")));
		mikrotik_conn_speed_attribute.set_type(radius.MIKROTIK_RATE_LIMIT);

		mikrotik_total_limit_attribute = radius.MikroTikAttribute();
		mikrotik_total_limit_attribute.set_value(struct.pack(">I", int(bytes_remaining % (4 * 1024 * 1024))));
		mikrotik_total_limit_attribute.set_type(radius.MIKROTIK_TOTAL_LIMIT);
		#mikrotik_total_limit_attribute.set_type(radius.MIKROTIK_SEND_LIMIT);

		mikrotik_total_limit_giga_attribute = radius.MikroTikAttribute();
		mikrotik_total_limit_giga_attribute.set_value(struct.pack(">I", int(bytes_remaining / (4 * 1024 * 1024))));
		mikrotik_total_limit_giga_attribute.set_type(radius.MIKROTIK_TOTAL_GIGAWORDS_LIMIT);
	
		mikrotik_recv_limit_attribute = radius.MikroTikAttribute();
		mikrotik_recv_limit_attribute.set_value(struct.pack(">I", int(bytes_remaining % (4 * 1024 * 1024))));
		mikrotik_recv_limit_attribute.set_type(radius.MIKROTIK_RECV_LIMIT);

		mikrotik_recv_limit_giga_attribute = radius.MikroTikAttribute();
		mikrotik_recv_limit_giga_attribute.set_value(struct.pack(">I", int(bytes_remaining / (4 * 1024 * 1024))));
		mikrotik_recv_limit_giga_attribute.set_type(radius.MIKROTIK_RECV_GIGAWORDS_LIMIT);
		
		conn_speed_attribute = (
			radius.RADIUSVendorSpecificAttribute(
				radius.RADIUS_VENDOR_SPECIFIC_ATTRIBUTE, 
				radius.RADIUS_MIKROTIK_VENDOR_ID,
				mikrotik_conn_speed_attribute.get_bytes()));
		radius_success.add_attribute(conn_speed_attribute);

		total_limit_attribute = (
			radius.RADIUSVendorSpecificAttribute(
				radius.RADIUS_VENDOR_SPECIFIC_ATTRIBUTE, 
				radius.RADIUS_MIKROTIK_VENDOR_ID,
				mikrotik_total_limit_attribute.get_bytes()));
		radius_success.add_attribute(total_limit_attribute);
	
		total_limit_giga_attribute = (
			radius.RADIUSVendorSpecificAttribute(
				radius.RADIUS_VENDOR_SPECIFIC_ATTRIBUTE, 
				radius.RADIUS_MIKROTIK_VENDOR_ID,
				mikrotik_total_limit_giga_attribute.get_bytes()));
		radius_success.add_attribute(total_limit_giga_attribute);

		recv_limit_giga_attribute = (
			radius.RADIUSVendorSpecificAttribute(
				radius.RADIUS_VENDOR_SPECIFIC_ATTRIBUTE, 
				radius.RADIUS_MIKROTIK_VENDOR_ID,
				mikrotik_recv_limit_giga_attribute.get_bytes()));
		#radius_success.add_attribute(recv_limit_giga_attribute);


		send_key_attribute = (
			radius.RADIUSVendorSpecificAttribute(
				radius.RADIUS_VENDOR_SPECIFIC_ATTRIBUTE, 
				radius.RADIUS_MICROSOFT_VENDOR_ID,
				microsoft_send_key_attribute.get_bytes()));
		radius_success.add_attribute(send_key_attribute);

		recv_key_attribute = (
			radius.RADIUSVendorSpecificAttribute(
				radius.RADIUS_VENDOR_SPECIFIC_ATTRIBUTE, 
				radius.RADIUS_MICROSOFT_VENDOR_ID,
				microsoft_recv_key_attribute.get_bytes()));
		radius_success.add_attribute(recv_key_attribute);

		message_authenticator_attribute = (
			radius.RADIUSAttribute(
				radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE, 
				[0] * radius.RADIUS_AUTHENTICATOR_FIELD_LENGTH));
		radius_success.add_attribute(message_authenticator_attribute);
		message_authentication_bytes = (
			Utils.Utils.compute_message_authentication(radius_success, 
				bytearray(config["security"]["radius_master_secret"], encoding='utf8')));
		radius_success = Utils.Utils.set_message_authentication(radius_success, message_authentication_bytes);
		response_authenticator = Utils.Utils.compute_response_authenticator(radius_success,
			bytearray(config["security"]["radius_master_secret"], encoding='utf8'));
		radius_success.set_authenticator(response_authenticator);
		bytes_out = socket.sendto(bytearray(radius_success.get_bytes()), address);
		print("Sent %d" % (bytes_out));

	@staticmethod
	def process_encrypted_alert(tls_state, tls_packet):
		packet_bytes = bytearray(tls_packet.get_records()[0].get_bytes_without_header());
		key = tls_state.get_client_write_cipher_key();
		iv = packet_bytes[0:aes.IV_SIZE];
		cipher = aes.AESCipher(aes.AES_CBC_MODE, key, iv);
		decrypted_bytes = cipher.decrypt(packet_bytes[aes.IV_SIZE:len(packet_bytes)]);
	@staticmethod
	def handle_accounting_response(
		authenticator,
		radius_identifier,
		socket,
		address):
		"""
		Radius accounting response
		"""
		radius_accounting_response = radius.RADIUSPacket();
		"""
		Set the code of the RADIUS packet to challenge type
		"""
		radius_accounting_response.set_code(radius.RADIUS_ACCOUNTING_RESPONSE_TYPE);
		"""
		Set correct value of the authenticator field
		"""
		radius_accounting_response.set_authenticator(authenticator);
		"""
		Set the identifier so that the NAS can match request with response
		"""
		radius_accounting_response.set_identifier(radius_identifier);

		"""
		Compute resposne authenticator
		"""
		response_authenticator = Utils.Utils.compute_response_authenticator(radius_accounting_response,
			bytearray(config["security"]["radius_master_secret"], encoding='utf8'));
		radius_accounting_response.set_authenticator(response_authenticator);
		"""
		Send response packet 
		"""
		bytes_out = socket.sendto(bytearray(radius_accounting_response.get_bytes()), address);
		print("Sent %d" % (bytes_out));