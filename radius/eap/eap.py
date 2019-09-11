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
EAP TTLS is described in RFC 5281
https://tools.ietf.org/html/rfc5281
https://tools.ietf.org/html/rfc3748
"""
from binascii import hexlify

EAP_TTLS_REUQUEST_CODE               = 0x1;
EAP_TTLS_RESPONSE_CODE               = 0x2;

EAP_SUCCESS                          = 0x3;
EAP_FAILURE                          = 0x4;

EAP_TTLS_CODE_FIELD_LENGTH           = 0x1;
EAP_TTLS_CODE_FIELD_OFFSET           = 0x0;

EAP_TTLS_IDENTIFIER_FIELD_LENGTH     = 0x1;
EAP_TTLS_IDENTIFIER_FIELD_OFFSET     = 0x1;

EAP_TTLS_LENGTH_FIELD_LENGTH         = 0x2;
EAP_TTLS_LENGTH_FIELD_OFFSET         = 0x2;

EAP_TTLS_TYPE_FIELD_LENGTH           = 0x1;
EAP_TTLS_TYPE_FIELD_OFFSET           = 0x4;

EAP_TTLS_FLAGS_FIELD_LENGTH          = 0x1;
EAP_TTLS_FLAGS_FIELD_OFFSET          = 0x5;

EAP_TLS_EXTENDED_LENGTH_FIELD_OFFSET = 0x6;
EAP_TLS_EXTENDED_LENGTH_FIELD_LENGTH = 0x4;

EAP_TTLS_TYPE                        = 0x15;
EAP_IDENTITY_TYPE                    = 0x1;

IS_LENGTH_INCLUDED                   = (lambda flags: (flags & 0x80 == 0x80));
HAS_MORE_FRAGMENTS                   = (lambda flags: (flags & 0x40 == 0x40));
IS_START_PACKET                      = (lambda flags: (flags & 0x20 == 0x20));

EAP_CODE_FIELD_OFFSET                = 0x0;
EAP_TYPE_FIELD_OFFSET                = 0x4;
EAP_ID_FIELD_OFFSET                  = 0x1;
EAP_LENGTH_FIELD_OFFSET              = 0x2;
EAP_DATA_OFFSET                      = 0x5;
EAP_TTLS_DATA_OFFSET                 = 0x6;

EAP_CODE_FIELD_LENGTH                = 0x1;
EAP_ID_FIELD_LENGTH                  = 0x1;
EAP_LENGTH_FIELD_LENGTH              = 0x2;

EAP_SUCCESS_LENGTH                   = 0x4;

class EAPPacket():
	"""
	Basic EAP packet
	"""
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = [0] * (EAP_CODE_FIELD_LENGTH + EAP_ID_FIELD_LENGTH + EAP_LENGTH_FIELD_LENGTH);

	def get_code(self):
		"""
		Gets the code of the EAP packet
		"""
		return self.buffer[EAP_CODE_FIELD_OFFSET];
	def set_code(self, code):
		"""
		Sets EAP code
		"""
		self.buffer[EAP_CODE_FIELD_OFFSET] = code;
	def get_type(self):
		"""
		Gets the type of the EAP packet
		"""
		return self.buffer[EAP_TYPE_FIELD_OFFSET];
	def get_identifier(self):
		"""
		Gets identifier of the EAP packet
		"""
		return self.buffer[EAP_ID_FIELD_OFFSET];
	def get_length(self):
		"""
		Gets the length of the packet
		"""
		return (self.buffer[EAP_LENGTH_FIELD_OFFSET] << 8) | (self.buffer[EAP_LENGTH_FIELD_OFFSET + 1])
	def set_length(self, length):
		self.buffer[EAP_LENGTH_FIELD_OFFSET] = (length >> 8) & 0xFF;
		self.buffer[EAP_LENGTH_FIELD_OFFSET + 1] = length & 0xFF;
	def get_bytes(self):
		"""
		Retuns raw packet bytes including the header
		"""
		return self.buffer;
	def get_bytes_without_header(self):
		"""
		Returns the raw bytes without EAP header
		"""

		return self.buffer[EAP_DATA_OFFSET:len(self.buffer)];


class EAPTTLSPacket():
	def __init__(self, buffer = None):
		"""
		EAPTTLS packet base class
		"""
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = ([0] * (EAP_TTLS_CODE_FIELD_LENGTH + 
							EAP_TTLS_IDENTIFIER_FIELD_LENGTH +
							EAP_TTLS_LENGTH_FIELD_LENGTH +
							EAP_TTLS_FLAGS_FIELD_LENGTH +  
							EAP_TTLS_TYPE_FIELD_LENGTH)
							);
			self.set_length((EAP_TTLS_CODE_FIELD_LENGTH + 
							EAP_TTLS_IDENTIFIER_FIELD_LENGTH +
							EAP_TTLS_LENGTH_FIELD_LENGTH + 
							EAP_TTLS_FLAGS_FIELD_LENGTH + 
							EAP_TTLS_TYPE_FIELD_LENGTH));
		self.buffer[EAP_TTLS_TYPE_FIELD_OFFSET] = EAP_TTLS_TYPE;

	def get_code(self):
		"""
		Gets the code of the packet it can be either reponse or request 
		"""
		return self.buffer[EAP_TTLS_CODE_FIELD_OFFSET];
	def set_code(self, code):
		"""
		Sets the code of the packet
		"""
		self.buffer[EAP_TTLS_CODE_FIELD_OFFSET] = code;
	def get_identifier(self):
		"""
		Get packet identifier
		"""
		return self.buffer[EAP_TTLS_IDENTIFIER_FIELD_OFFSET];
	def set_identifier(self, identifier):
		"""
		Sets identifier of the EAP packet
		"""
		self.buffer[EAP_TTLS_IDENTIFIER_FIELD_OFFSET] = identifier;
	def get_length(self):
		"""
		Gets the length of the packet in octets.
		The Length field is two octets and indicates the number of octets
  	    in the entire EAP packet, from the Code field through the Data
     	field.
		"""
		return (((self.buffer[EAP_TTLS_LENGTH_FIELD_OFFSET] << 8) & 0xFF) |
			(self.buffer[EAP_TTLS_LENGTH_FIELD_OFFSET + 1] & 0xFF));
	def set_length(self, length):
		"""
		Sets the length of the packet
		"""
		self.buffer[EAP_TTLS_LENGTH_FIELD_OFFSET] = ((length >> 8) & 0xFF);
		self.buffer[EAP_TTLS_LENGTH_FIELD_OFFSET + 1] = (length & 0xFF);
	def get_type(self):
		"""
		Gets packet type. It should always be EAP_TTLS_TYPE
		"""
		self.buffer[EAP_TTLS_TYPE_FIELD_OFFSET];		
	def get_flags(self):
		"""
		Gets the flags
		"""
		return self.buffer[EAP_TTLS_FLAGS_FIELD_OFFSET];
	def set_length_included_flag(self):
		"""
		Sets the length included flag to 1		
		"""
		self.buffer[EAP_TTLS_FLAGS_FIELD_OFFSET] |= 0x80;

	def has_more_fragments_flag(self):
		"""
		Returns boolean True if packet has more fragments flag set
		"""
		return (self.buffer[EAP_TTLS_FLAGS_FIELD_OFFSET] & 0x40 == 0x40);
	def set_has_more_fragments_flag(self):
		"""
		Sets has more fragments flag to 1
		"""
		self.buffer[EAP_TTLS_FLAGS_FIELD_OFFSET] |= 0x40;
	def set_is_start_flag(self):
		"""
		Sets is start flag to 1
		"""
		self.buffer[EAP_TTLS_FLAGS_FIELD_OFFSET] |= 0x20;
	def get_bytes(self):
		"""
		Returns raw buffer bytes
		"""
		return self.buffer;
	def get_bytes_without_header(self):
		"""
		Returns the raw bytes without EAP TTLS header
		"""
		if (self.buffer[EAP_TTLS_FLAGS_FIELD_OFFSET] & 0x80):
			return self.buffer[EAP_TTLS_DATA_OFFSET + EAP_TLS_EXTENDED_LENGTH_FIELD_LENGTH:len(self.buffer)];
		else:
			return self.buffer[EAP_TTLS_DATA_OFFSET:len(self.buffer)];
	def set_payload(self, payload, total_length):
		length = self.get_length();
		if (self.buffer[EAP_TTLS_FLAGS_FIELD_OFFSET] & 0x80 == 0x80):
			offset = EAP_TLS_EXTENDED_LENGTH_FIELD_OFFSET;
			self.buffer[len(self.buffer):len(self.buffer) + EAP_TLS_EXTENDED_LENGTH_FIELD_LENGTH] = [0x0, 0x0, 0x0, 0x0];
			self.buffer[offset] = (total_length >> 24) & 0xFF;
			self.buffer[offset + 1] = (total_length >> 16) & 0xFF;
			self.buffer[offset + 2] = (total_length >> 8) & 0xFF;
			self.buffer[offset + 3] = (total_length) & 0xFF;
			offset += EAP_TLS_EXTENDED_LENGTH_FIELD_LENGTH;
			self.buffer[offset:offset+len(payload)] = payload;
			self.set_length(length + len(payload) + EAP_TLS_EXTENDED_LENGTH_FIELD_LENGTH);
		else:
			offset = EAP_TTLS_FLAGS_FIELD_OFFSET;
			self.set_length(length + len(payload));
			self.buffer[len(self.buffer):len(self.buffer) + len(payload)] = payload;
			#self.set_length(length + len(payload));
	def get_total_length(self):
		"""
		Gets total length of all fragments
		"""
		offset = EAP_TLS_EXTENDED_LENGTH_FIELD_OFFSET;
		if (self.buffer[EAP_TTLS_FLAGS_FIELD_OFFSET] & 0x80 == 0x80):
			return ((self.buffer[offset] << 24) | 
				(self.buffer[offset + 1] << 16) |
				(self.buffer[offset + 2] << 8) |
				(self.buffer[offset + 3]));
		return None;

class EAPTTLSRequest(EAPTTLSPacket):
	def __init__(self, buffer = None):
		"""
		EAPTTLS packet base class
		"""
		EAPTTLSPacket.__init__(self, buffer);
		self.set_code(EAP_TTLS_REUQUEST_CODE);

class EAPTTLSResponse(EAPTTLSPacket):
	def __init__(self, buffer = None):
		"""
		EAPTTLS packet base class
		"""
		EAPTTLSPacket.__init__(self, buffer);
		self.set_code(EAP_TTLS_RESPONSE_CODE);

class EAPSuccess(EAPPacket):
	def __init__(self, buffer = None):
		"""
		EAPTTLS packet base class
		"""
		EAPPacket.__init__(self, buffer);
		self.set_code(EAP_SUCCESS);
		self.set_length(EAP_SUCCESS_LENGTH);

class EAPFailure(EAPPacket):
	def __init__(self, buffer = None):
		"""
		EAPTTLS packet base class
		"""
		EAPPacket.__init__(self, buffer);
		self.set_code(EAP_FAILURE);
		self.set_length(EAP_SUCCESS_LENGTH);

"""
Fields lengths and offsets
"""
AVP_CODE_LENGTH             = 0x4;
AVP_CODE_OFFSET             = 0x0;

AVP_FLAGS_LENGTH            = 0x1;
AVP_FLAGS_OFFSET            = 0x4;

AVP_LENGTH_OFFSET           = 0x5;
AVP_LENGTH_LENGTH           = 0x3;

AVP_VENDOR_ID_OFFSET        = 0x8;
AVP_VENDOR_ID_LENGTH        = 0x4;
AVP_DATA_OFFSET             = 0x8;

PAP_USERNAME_ATTRIBUTE_CODE = 0x1;
PAP_PASSWORD_ATTRBIUTE_CODE = 0x2;

class ParseAVP():
	@staticmethod
	def parse(buffer):
		has_more_avp = True;
		offset = 0;
		avps = [];
		while has_more_avp:
			length = ((buffer[offset + AVP_LENGTH_OFFSET] << 16) |
				(buffer[offset + AVP_LENGTH_OFFSET + 1] << 8) |
				(buffer[offset + AVP_LENGTH_OFFSET + 2]));
			# https://tools.ietf.org/html/rfc5281#section-11.2.5
			# https://tools.ietf.org/html/rfc5281#section-10.1
			avps.append(EAPTTLSAVP(buffer[offset:offset + length]));
			if length % 0x4 != 0x0:
				offset += length + (0x4 - length % 0x4);
			else:
				offset += length;
			if offset == len(buffer):
				has_more_avp = False;
		return avps;


class EAPTTLSAVP():
	"""
	EAP TTLS Attribute value pairs
	"""
	def __init__(self, buffer):
		"""
		Initializes the EAP TTLS attribute value pair. If 
		buffer is empty, the constructor initializes the buffer
		with zeros
		"""
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = ([0] * (AVP_CODE_LENGTH + AVP_FLAGS_LENGTH + AVP_LENGTH_LENGTH))
	def get_code(self):
		"""
		Gets the code value from the attribute
		"""
		return ((self.buffer[AVP_CODE_OFFSET] << 24) |
				(self.buffer[AVP_CODE_OFFSET + 1] << 16) |
				(self.buffer[AVP_CODE_OFFSET + 2] << 8) |
				(self.buffer[AVP_CODE_OFFSET + 3]));
	def get_flags(self):
		"""
		Returns flags
		"""
		return (self.buffer[AVP_FLAGS_OFFSET]);
	def get_length(self):
		return ((self.buffer[AVP_LENGTH_OFFSET] << 16) |
				(self.buffer[AVP_LENGTH_OFFSET + 1] << 8) |
				(self.buffer[AVP_LENGTH_OFFSET + 2]));
	def get_data(self):
		"""
		Gets the value associated with the attribute. 
		If vendor ID flag is set, vendor ID will be skipped
		and only raw value will be returned.
		"""
		is_vendor_flag_set = self.buffer[AVP_FLAGS_OFFSET] & 0x80;
		vendor_id_length = 0x0;
		if is_vendor_flag_set == 0x80:
			vendor_id_length = AVP_VENDOR_ID_LENGTH;
		offset = AVP_DATA_OFFSET + vendor_id_length;
		length = ((self.buffer[AVP_LENGTH_OFFSET] << 16) |
					(self.buffer[AVP_LENGTH_OFFSET + 1] << 8) |
					(self.buffer[AVP_LENGTH_OFFSET + 2]));
		length -= AVP_CODE_LENGTH - AVP_FLAGS_LENGTH - AVP_LENGTH_LENGTH;
		if is_vendor_flag_set:
			length -= AVP_VENDOR_ID_LENGTH;
		return self.buffer[offset:offset + length]; 