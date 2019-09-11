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

"""
Base RADIUS is described in RFC 2865
https://tools.ietf.org/html/rfc2865
EAP Message attribute
https://tools.ietf.org/html/rfc2869
"""
# Basic RADIUS packet types
RADIUS_ACCESS_REQUEST_TYPE                 = 0x1;
RADIUS_ACCESS_ACCEPT_TYPE                  = 0x2;
RADIUS_ACCESS_REJECT_TYPE                  = 0x3;
RADIUS_ACCOUNTING_REQUEST_TYPE             = 0x4;
RADIUS_ACCOUNTING_RESPONSE_TYPE            = 0x5;
RADIUS_ACCESS_CHALLENGE_TYPE               = 0xB;

# RADIUS fields length and offsets
RADIUS_CODE_FIELD_LENGTH                   = 0x1;
RADIUS_CODE_FIELD_OFFSET                   = 0x0;

RADIUS_IDENTIFIER_FIELD_LENGTH             = 0x1;
RADIUS_IDENTIFIER_FIELD_OFFSET             = 0x1;

RADIUS_LENGTH_FIELD_LENGTH                 = 0x2;
RADIUS_LENGTH_FIELD_OFFSET                 = 0x2;

RADIUS_AUTHENTICATOR_FIELD_LENGTH          = 0x10;
RADIUS_AUTHENTICATOR_FIELD_OFFSET          = 0x4;

RADIUS_EAP_MESSAGE_ATTRIBUTE               = 0x4f;
RADIUS_EAP_MESSAGE_AUTHENTICATOR_ATTRIBUTE = 0x50;
RADIUS_CALLING_STATION_ID_ATTRIBUTE        = 0x1f;
RADIUS_VENDOR_SPECIFIC_ATTRIBUTE           = 0x1a;

RADIUS_ATTRIBUTE_TYPE_LENGTH               = 0x1;
RADIUS_ATTRIBUTE_LENGTH_LENGTH             = 0x1;
RADIUS_ATTRIBUTE_VENDOR_LENGTH             = 0x4;

RADIUS_MAXIMIUM_ATTRIBUTE_LENGTH           = 0x100;

RADIUS_MIKROTIK_VENDOR_ID                  = 0x3a8c;
RADIUS_MICROSOFT_VENDOR_ID                 = 0x137;

MIKROTIK_WIRELESS_ENC_KEY                  = 0x10;

MIKROTIK_WIRELESS_ENC_ALG                  = 0x6;

MIKROTIK_WIRELESS_ENC_ALG_VALUE            = [0x3];

MIKROTIK_WIRELESS_ENC_KEY_LENGTH           = 0x30;
MIKROTIK_WIRELESS_ENC_KEY_OFFSET           = 0x0;

MIKROTIK_ATTRIBUTE_LENGTH_LENGTH           = 0x1;
MIKROTIK_ATTRIBUTE_TYPE_LENGTH             = 0x1;

MIKROTIK_ATTRIBUTE_TYPE_OFFSET             = 0x0;
MIKROTIK_ATTRIBUTE_LENGTH_OFFSET           = 0x1;

MIKROTIK_ATTRIBUTE_VALUE_OFFSET            = 0x2;

MS_MPPE_RECV_KEY                           = 0x11;
MS_MPPE_SEND_KEY                           = 0x10;

MIKROTIK_RECV_LIMIT                        = 0x1;
MIKROTIK_SEND_LIMIT                        = 0x2;
MIKROTIK_TOTAL_LIMIT                       = 0x11;
MIKROTIK_TOTAL_GIGAWORDS_LIMIT             = 0x12;
MIKROTIK_RATE_LIMIT                        = 0x8;
MIKROTIK_RECV_GIGAWORDS_LIMIT              = 0x0e;


class MikroTikAttribute():
	"""
	https://tools.ietf.org/html/rfc2865#section-5.26
	"""
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = [0x0] * (MIKROTIK_ATTRIBUTE_LENGTH_LENGTH + MIKROTIK_ATTRIBUTE_TYPE_LENGTH);
	def set_type(self, vendor_type):
		self.buffer[MIKROTIK_ATTRIBUTE_TYPE_OFFSET] = vendor_type & 0xFF;
	def get_type(self):
		return self.buffer[MIKROTIK_ATTRIBUTE_TYPE_OFFSET];
	def get_length(self):
		self.buffer[MIKROTIK_ATTRIBUTE_LENGTH_OFFSET];
	def set_length(self, length):
		self.buffer[MIKROTIK_ATTRIBUTE_LENGTH_OFFSET] = length & 0xFF;
	def set_value(self, value):
		offset = MIKROTIK_ATTRIBUTE_VALUE_OFFSET;
		self.buffer[offset:offset + len(value)] = value;
		self.set_length(MIKROTIK_ATTRIBUTE_LENGTH_LENGTH + MIKROTIK_ATTRIBUTE_TYPE_LENGTH + len(value));
	def get_value(self):
		length = self.get_length() - MIKROTIK_ATTRIBUTE_LENGTH_LENGTH - MIKROTIK_ATTRIBUTE_TYPE_LENGTH;
		offset = MIKROTIK_ATTRIBUTE_VALUE_OFFSET;
		return self.buffer[offset:offset + length];
	def get_bytes(self):
		return self.buffer;


MICROSOFT_ATTRIBUTE_LENGTH_LENGTH = 0x1;
MICROSOFT_ATTRIBUTE_TYPE_LENGTH = 0x1;

MICROSOFT_ATTRIBUTE_TYPE_OFFSET = 0x0;
MICROSOFT_ATTRIBUTE_LENGTH_OFFSET = 0x1;

MICROSOFT_ATTRIBUTE_VALUE_OFFSET = 0x2;

class MicrosoftAttribute():
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = [0x0] * (MICROSOFT_ATTRIBUTE_LENGTH_LENGTH + MICROSOFT_ATTRIBUTE_TYPE_LENGTH);
	def set_type(self, vendor_type):
		self.buffer[MICROSOFT_ATTRIBUTE_TYPE_OFFSET] = vendor_type & 0xFF;
	def get_type(self):
		return self.buffer[MICROSOFT_ATTRIBUTE_TYPE_OFFSET];
	def get_length(self):
		self.buffer[MICROSOFT_ATTRIBUTE_LENGTH_OFFSET];
	def set_length(self, length):
		self.buffer[MICROSOFT_ATTRIBUTE_LENGTH_OFFSET] = length & 0xFF;
	def set_value(self, value):
		offset = MICROSOFT_ATTRIBUTE_VALUE_OFFSET;
		self.buffer[offset:offset + len(value)] = value;
		self.set_length(MICROSOFT_ATTRIBUTE_LENGTH_LENGTH + MICROSOFT_ATTRIBUTE_TYPE_LENGTH + len(value));
	def get_value(self):
		length = self.get_length() - MICROSOFT_ATTRIBUTE_LENGTH_LENGTH - MICROSOFT_ATTRIBUTE_TYPE_LENGTH;
		offset = MICROSOFT_ATTRIBUTE_VALUE_OFFSET;
		return self.buffer[offset:offset + length];
	def get_bytes(self):
		return self.buffer;

class RADIUSAttribute():
	def __init__(self, type_code, value):
		"""
		Initializes the RADIUS attribute
		"""
		self.type = type_code;
		self.length = (len(value) + 
						RADIUS_ATTRIBUTE_TYPE_LENGTH + 
						RADIUS_ATTRIBUTE_LENGTH_LENGTH);
		self.value = value;
	def get_type(self):
		"""
		Returns the type of the attribute
		"""
		return self.type;
	def get_value(self):
		"""
		Returns the value of the attribute
		"""
		return self.value;
	def get_length(self):
		"""
		Returns the length of the attribute
		"""
		return self.value;
	def get_bytes(self):
		"""
		Returns raw attribute bytes
		"""

		raw = [0] * (self.length);
		raw[0] = self.type;
		raw[1] = self.length;
		raw[2:self.length] = self.value;
		return raw;

class RADIUSVendorSpecificAttribute(RADIUSAttribute):
	def __init__(self, type_code, vendor, value):
		"""
		Initializes the RADIUS attribute
		"""
		self.type = type_code;
		self.length = (len(value) + 
						RADIUS_ATTRIBUTE_TYPE_LENGTH + 
						RADIUS_ATTRIBUTE_LENGTH_LENGTH + 
						RADIUS_ATTRIBUTE_VENDOR_LENGTH);
		#print(self.length);
		self.vendor_id = vendor;
		self.value = value;
	def get_type(self):
		"""
		Returns the type of the attribute
		"""
		return self.type;
	def get_value(self):
		"""
		Returns the value of the attribute
		"""
		return self.value;
	def get_length(self):
		"""
		Returns the length of the attribute
		"""
		return self.value;
	def get_bytes(self):
		"""
		Returns raw attribute bytes
		"""
		offset = 0;
		raw = [0] * (self.length);
		raw[offset] = self.type;
		raw[offset + 1] = self.length;
		raw[offset + 2] = ((self.vendor_id >> 24) & 0xFF);
		raw[offset + 3] = ((self.vendor_id >> 16) & 0xFF);
		raw[offset + 4] = ((self.vendor_id >> 8) & 0xFF);
		raw[offset + 5] = (self.vendor_id & 0xFF);
		raw[offset + 6:self.length] = self.value;
		return raw;

class RADIUSPacket():
	def __init__(self, buffer = None):
		"""
		Initializes the RADIUS packet
		"""
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = (
					[0] * 
					(RADIUS_CODE_FIELD_LENGTH +
					RADIUS_IDENTIFIER_FIELD_LENGTH +
					RADIUS_LENGTH_FIELD_LENGTH +
					RADIUS_AUTHENTICATOR_FIELD_LENGTH)
				);
			self.set_length((RADIUS_CODE_FIELD_LENGTH +
					RADIUS_IDENTIFIER_FIELD_LENGTH +
					RADIUS_LENGTH_FIELD_LENGTH +
					RADIUS_AUTHENTICATOR_FIELD_LENGTH));
	def set_code(self, code):
		"""
		Sets the code of the packet
		"""
		self.buffer[RADIUS_CODE_FIELD_OFFSET] = code;
	def get_code(self):
		"""
		Gets the RADIUS code
		"""
		return self.buffer[RADIUS_CODE_FIELD_OFFSET];
	def set_identifier(self, id):
		"""
		Sets the identifier 
		"""
		self.buffer[RADIUS_IDENTIFIER_FIELD_OFFSET] = id;
	def get_identifier(self):
		"""
		Gets the identifier
		"""
		return self.buffer[RADIUS_IDENTIFIER_FIELD_OFFSET];
	def get_length(self):
		"""
		Gets the length of the RADIUS packet
		"""
		return ((self.buffer[RADIUS_LENGTH_FIELD_OFFSET] << 8) |
				self.buffer[RADIUS_LENGTH_FIELD_OFFSET + 1]);
	def set_length(self, length):
		"""
		Sets the length of the RADIUS packet
		"""
		self.buffer[RADIUS_LENGTH_FIELD_OFFSET] = ((length >> 8) & 0xFF);
		self.buffer[RADIUS_LENGTH_FIELD_OFFSET + 1] = (length & 0xFF);
	def get_authenticator(self):
		"""
		Gets the authenticator field
		"""
		offset = RADIUS_AUTHENTICATOR_FIELD_OFFSET;
		length = RADIUS_AUTHENTICATOR_FIELD_LENGTH;
		return self.buffer[offset:offset + length];
	def set_authenticator(self, authenticator):
		"""
		Sets authenticator
		"""
		if len(authenticator) != RADIUS_AUTHENTICATOR_FIELD_LENGTH:
			raise Exception("Invalid authenticator bytes");
		offset = RADIUS_AUTHENTICATOR_FIELD_OFFSET;
		length = RADIUS_AUTHENTICATOR_FIELD_LENGTH;
		self.buffer[offset:offset + length] = authenticator;
	def get_attributes(self):
		"""
		Gets the attributes of the RADIUS packet
		"""
		attributes_length = (self.get_length() - 
			RADIUS_CODE_FIELD_LENGTH -
			RADIUS_IDENTIFIER_FIELD_LENGTH - 
			RADIUS_LENGTH_FIELD_LENGTH - 
			RADIUS_AUTHENTICATOR_FIELD_LENGTH);
		offset = (RADIUS_AUTHENTICATOR_FIELD_OFFSET + 
			RADIUS_AUTHENTICATOR_FIELD_LENGTH);
		attributes = [];
		if attributes_length > 0:
			has_more_attributes = True;
			while has_more_attributes:
				attribute_type = self.buffer[offset];
				attribute_length = self.buffer[offset + 1];
				attribute_value = self.buffer[offset + 2:offset + attribute_length];
				attributes.append(RADIUSAttribute(attribute_type, attribute_value));
				offset += attribute_length;
				if offset == len(self.buffer):
					has_more_attributes = False;
		return attributes;
	def add_attribute(self, attribute):
		"""
		Adds attribute to the RADIUS packet 
		and updates the packet length
		by the length of the attribute
		"""
		length = self.get_length();
		attribute = attribute.get_bytes();
		self.buffer[len(self.buffer):len(self.buffer) + len(attribute)] = attribute;
		self.set_length(length + len(attribute));
	def get_bytes(self):
		"""
		Returns raw buffer
		"""
		return self.buffer;
