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

from crypto import digest;
from radius import radius;

import math

class Utils():
	"""
	This class should be combined with the Utils class located in crypto folder
	"""
	@staticmethod
	def compare_bytearrays(l, r):
		"""
		Compares two arrays byte by byte
		"""
		if len(l) != len(r):
			return False;
		for i in range(0, len(l)):
			if l[i] != r[i]:
				return False;
		return True;
	@staticmethod
	def compute_response_authenticator(radius_packet, secret):
		"""
		Computes response authenticator field for the packet

		Computes RADIUS response authenticator as described in RFC 2865:
		https://tools.ietf.org/html/rfc2865#section-3

		The value of the Authenticator field in Access-Accept, Access-
		Reject, and Access-Challenge packets is called the Response
		Authenticator, and contains a one-way MD5 hash calculated over
		a stream of octets consisting of: the RADIUS packet, beginning
		with the Code field, including the Identifier, the Length, the
		Request Authenticator field from the Access-Request packet, and
		the response Attributes, followed by the shared secret.  That
		is:
		
		ResponseAuth = MD5(Code | ID | Length | RequestAuth | Attributes | Secret)

		where | denotes concatenation

		"""
		md5 = digest.MD5Digest();
		return md5.digest(bytearray(radius_packet.get_bytes()) + secret);
	@staticmethod
	def set_message_authentication(radius_packet, authentication_message):
		"""
		Sets the value of the message authentication attribute

		This is rather wrong way of doing things. Perhaps, in future, 
		we may set attribute values directly in the packet.
		"""
		radius_packet_copy = radius.RADIUSPacket();
		radius_packet_copy.set_code(radius_packet.get_code());
		radius_packet_copy.set_identifier(radius_packet.get_identifier());
		radius_packet_copy.set_authenticator(radius_packet.get_authenticator());
		attributes = radius_packet.get_attributes();
		for attribute in attributes:
			if attribute.get_type() == radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE:
				attribute = radius.RADIUSAttribute(radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE, authentication_message);
			radius_packet_copy.add_attribute(attribute);
		return radius_packet_copy;
	@staticmethod
	def compute_message_authentication(radius_packet, secret):
		"""
		Computes message authentication code for the given RADIUS packet.

		For Access-Challenge, Access-Accept, and Access-Reject packets,
		the Message-Authenticator is calculated as follows, using the
		Request-Authenticator from the Access-Request this packet is in
		reply to:

		Message-Authenticator = HMAC-MD5 (Type, Identifier, Length,
											Request Authenticator, Attributes)
		
		When the message integrity check is calculated the signature
		string should be considered to be sixteen octets of zero.  The
		shared secret is used as the key for the HMAC-MD5 message
		integrity check.  The Message-Authenticator is calculated and
		inserted in the packet before the Response Authenticator is
		calculated.

		"""
		radius_packet_copy = radius.RADIUSPacket();
		radius_packet_copy.set_code(radius_packet.get_code());
		radius_packet_copy.set_identifier(radius_packet.get_identifier());
		radius_packet_copy.set_authenticator(radius_packet.get_authenticator());
		attributes = radius_packet.get_attributes();
		authentication_message = None;
		for attribute in attributes:
			if attribute.get_type() == radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE:
				authentication_message = attribute.get_value();
				# Set Message-Authentication attribute value to 16 zero bytes
				attribute = radius.RADIUSAttribute(radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE, [0]*radius.RADIUS_AUTHENTICATOR_FIELD_LENGTH);
			radius_packet_copy.add_attribute(attribute);
		md5hmac = digest.HMACMD5();
		return md5hmac.digest(secret, bytearray(radius_packet_copy.get_bytes()));
	@staticmethod
	def verify_accounting_authenticator(radius_packet, secret):
		authenticator = radius_packet.get_authenticator();
		radius_packet_copy = radius.RADIUSPacket();
		radius_packet_copy.set_code(radius_packet.get_code());
		radius_packet_copy.set_identifier(radius_packet.get_identifier());
		attributes = radius_packet.get_attributes();
		for attribute in attributes:			
			radius_packet_copy.add_attribute(attribute);
		md5 = digest.MD5Digest();
		authenticator_computed = md5.digest(bytearray(radius_packet_copy.get_bytes()) + secret);
		return Utils.compare_bytearrays(authenticator_computed, authenticator)
	@staticmethod
	def verify_message_authentication(radius_packet, secret):
		"""
		Verifies authenticity of the message

		When the message integrity check is calculated the signature
		string should be considered to be sixteen octets of zero.  The
		shared secret is used as the key for the HMAC-MD5 message
		integrity check.  The Message-Authenticator is calculated and
		inserted in the packet before the Response Authenticator is
		calculated.
		"""
		radius_packet_copy = radius.RADIUSPacket();
		radius_packet_copy.set_code(radius_packet.get_code());
		radius_packet_copy.set_identifier(radius_packet.get_identifier());
		radius_packet_copy.set_authenticator(radius_packet.get_authenticator());
		#authenticator = radius_packet_copy.get_authenticator();
		attributes = radius_packet.get_attributes();
		authentication_message = None;
		for attribute in attributes:
			if attribute.get_type() == radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE:
				authentication_message = attribute.get_value();
				# Set Message-Authentication attribute value to 16 zero bytes
				attribute = radius.RADIUSAttribute(radius.RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE, [0]*radius.RADIUS_AUTHENTICATOR_FIELD_LENGTH);
			radius_packet_copy.add_attribute(attribute);
		md5hmac = digest.HMACMD5();
		#computed_authenticator = md5.digest(bytearray(radius_packet_copy.get_bytes()) + bytearray(secret));
		authenticator_bytes = md5hmac.digest(secret, bytearray(radius_packet_copy.get_bytes()));
		return Utils.compare_bytearrays(authenticator_bytes, authentication_message)
	@staticmethod
	def get_calling_station_id(radius_packet):
		"""
		Searches for CALLING-STATION-ID in attrbiutes of RADIUS packet.
		If nothing is found then None value is returned.
		"""
		if not radius_packet:
			return None;
		attributes = radius_packet.get_attributes();
		for attribute in attributes:
			if attribute.get_type() == radius.RADIUS_CALLING_STATION_ID_ATTRIBUTE:
				return attribute.get_value();
		return None;
	@staticmethod
	def get_eap_packet(radius_packet):
		"""
		Reconstructs EAP packet from fragments found in EAP-MESSAGE attributes.
		If an exception occurs empty array will be returned.
		"""
		attributes = radius_packet.get_attributes();
		fragments = [];
		try:
			for attribute in attributes:
				if attribute.get_type() == radius.RADIUS_EAP_MESSAGE_ATTRIBUTE:
					fragments[len(fragments):len(fragments) + len(attribute.get_value())] = attribute.get_value();
			return fragments;
		except:
			return [];
	@staticmethod
	def radius_split_message(radius_packet, message, max_attribute_length):
		"""
		Splits EAP TTLS message and adds each part as RADIUS attrbite
		"""
		offset = 0;
		max_attrbutes = int(math.ceil(float(len(message)) / max_attribute_length));
		for i in range(0, max_attrbutes):
			if offset + max_attribute_length < len(message):
				length = max_attribute_length;
			else:
				length = len(message) - offset;
			eap_attribute = (
				radius.RADIUSAttribute(
					radius.RADIUS_EAP_MESSAGE_ATTRIBUTE, 
					message[offset:offset + length]));
			offset += length;
			radius_packet.add_attribute(eap_attribute);
		return radius_packet;
	