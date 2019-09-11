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

from utils import Utils;
#from radius import radius;

from eap import eap;
from tls import tls;
import radius;
#from radius import radius;
from radius import radius;
import crypto
from crypto import utils;
from crypto import certs;
from config import config;

config = config.config;

#help(radius);
from binascii import unhexlify;
from binascii import hexlify;

certificate = crypto.certs.X509v3Certificate.load("../config/certs/certificate.pem");

tls_packet = tls.TLSPacket();
record = tls.TLSRecordLayer();
server_hello_protocol = tls.TLSServerHelloProtocol();
server_random = utils.Utils.generate_random(tls.HANDSHAKE_SERVER_HELLO_RANDOM_LENGTH);
server_hello_protocol.set_random(server_random);
record.add_handshake_protocol(server_hello_protocol);

server_certificate_protocol = tls.TLSCertificateProtocol();
server_certificate_protocol.add_certificate(certificate);

record.add_handshake_protocol(server_certificate_protocol);
certificates = server_certificate_protocol.get_certificates();

server_hello_done_protocol = tls.TLSSeverHelloDoneProtocol();
record.add_handshake_protocol(server_hello_done_protocol);

tls_packet.add_record(record);

tls_packet_bytes = tls_packet.get_bytes();
max_eap_packet_size = 1000;

total_length = len(tls_packet_bytes);

has_more_eap_ttls_fragments = True;
is_first_fragment = True;
eap_identifier = 1;
offset = 0;
outstanding_packets = [];

"""
Split TLS packet into EAP packets
"""
while has_more_eap_ttls_fragments:
	eap_ttls_packet = eap.EAPTTLSRequest();
	eap_ttls_packet.set_identifier(eap_identifier);
	eap_identifier += 1;
	if offset + max_eap_packet_size < len(tls_packet_bytes):
		eap_ttls_packet.set_has_more_fragments_flag();
		if is_first_fragment:
			eap_ttls_packet.set_length_included_flag();
			is_first_fragment = False;
		print("-------------------------------------------------------");
		print(hexlify(bytearray(tls_packet_bytes[offset:offset+max_eap_packet_size])));
		print("-------------------------------------------------------");
		eap_ttls_packet.set_payload(tls_packet_bytes[offset:offset+max_eap_packet_size], total_length);
		#print(hexlify(bytearray(eap_ttls_packet.get_bytes())));
		#print(hexlify(bytearray(tls_packet_bytes[offset:offset + max_eap_packet_size])));
		outstanding_packets.append(eap_ttls_packet);
		offset = offset + max_eap_packet_size
	else:
		print("-------------------------------------------------------");
		print(hexlify(bytearray(tls_packet_bytes[offset:len(tls_packet_bytes)])));
		print("-------------------------------------------------------");
		eap_ttls_packet.set_payload(tls_packet_bytes[offset:len(tls_packet_bytes)], total_length);
		#print(hexlify(bytearray(tls_packet_bytes[offset:len(tls_packet_bytes)])));
		outstanding_packets.append(eap_ttls_packet);
		has_more_eap_ttls_fragments = False;
	print(hexlify(bytearray(eap_ttls_packet.get_bytes())));
	print(len(eap_ttls_packet.get_bytes()));

radius_packets = [];

"""
Split EAP message into RADIUS attributes
"""
for packet in outstanding_packets:
	radius_challenge = radius.RADIUSPacket();
	radius_challenge.set_code(radius.RADIUS_ACCESS_CHALLENGE_TYPE);
	radius_packets.append(Utils.Utils.radius_split_message(radius_challenge, packet.get_bytes(), 253));

b = [];


"""
Assemble TLS packets from EAP fragments encapsulated into radius attributes
"""
for radius_packet in radius_packets:
	eap_fragments = Utils.Utils.get_eap_packet(radius_packet);
	print(hexlify(bytes(eap_fragments)));
	eap_ttls_packet = eap.EAPTTLSRequest(eap_fragments);
	b += eap_ttls_packet.get_bytes_without_header();

tls_packet = tls.TLSPacket(b);
for record in tls_packet.get_records():
	print(record.get_version());
	for protocol in record.get_handshake_protocols(None):
		print(protocol.get_type())
