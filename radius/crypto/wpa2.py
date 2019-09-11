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

from crypto import utils;

from crypto.digest import SHA256Digest
from crypto.digest import SHA1Digest
from crypto.digest import HMACSHA256
from crypto.digest import MD5Digest

from binascii import hexlify

MSK_KEY_LENGTH  = 64;
EMSK_KEY_LENGTH = 64;

SEND_KEY_LENGTH = 32;
RECV_KEY_LENGTH = 32;

PRF_KEYING_MATERIAL_STRING_CONSTANT = "ttls keying material";

"""
MikroTik vendor specific attributes
https://wiki.mikrotik.com/wiki/Manual:RADIUS_Client#Access-Accept
https://wiki.mikrotik.com/wiki/Manual:RADIUS_Client/vendor_dictionary
https://security.stackexchange.com/questions/169352/can-someone-explain-in-simple-steps-how-wpa2-enterprise-authentication-and-encry/184446
https://freeradius.org/rfc/rfc3579.html
"""

class WPA2():
	"""
	Upon successful conclusion of an EAP-TTLS negotiation, 128 octets of
	keying material are generated and exported for use in securing the
	data connection between client and access point.  The first 64 octets
	of the keying material constitute the MSK, the second 64 octets
	constitute the EMSK.

	The keying material is generated using the TLS PRF function
	[RFC4346], with inputs consisting of the TLS master secret, the
	ASCII-encoded constant string "ttls keying material", the TLS client
	random, and the TLS server random.  The constant string is not null-
	terminated.

	Keying Material = PRF-128(SecurityParameters.master_secret, "ttls
		keying material", SecurityParameters.client_random +
		SecurityParameters.server_random)

	MSK = Keying Material [0..63]

	EMSK = Keying Material [64..127]

	The TTLS server distributes this keying material to the access point
	via the AAA carrier protocol.  When RADIUS is the AAA carrier
	protocol, the MPPE-Recv-Key and MPPE-Send-Key attributes [RFC2548]
	may be used to distribute the first 32 octets and second 32 octets of
	the MSK, respectively.

	Extended Master Session Key (EMSK)
	Master Session Key ()

	"""
	@staticmethod
	def generate_keying_material(master_secret, client_random, server_random):
		HMAC = HMACSHA256();
		seed = bytearray(str.encode(PRF_KEYING_MATERIAL_STRING_CONSTANT)) + client_random + server_random;
		A0 = seed;
		A1 = HMAC.digest(master_secret, A0);
		A2 = HMAC.digest(master_secret, A1);
		A3 = HMAC.digest(master_secret, A2);
		A4 = HMAC.digest(master_secret, A3);
		A5 = HMAC.digest(master_secret, A4);
		A6 = HMAC.digest(master_secret, A5);
		A7 = HMAC.digest(master_secret, A6);
		A8 = HMAC.digest(master_secret, A7);

		
		A = (HMAC.digest(master_secret, A1 + seed) + 
			HMAC.digest(master_secret, A2 + seed) + 
			HMAC.digest(master_secret, A3 + seed) +
			HMAC.digest(master_secret, A4 + seed) + 
			HMAC.digest(master_secret, A5 + seed) + 
			HMAC.digest(master_secret, A6 + seed) +
			HMAC.digest(master_secret, A7 + seed) +
			HMAC.digest(master_secret, A8 + seed));
		return A;

	@staticmethod
	def generate_msk(material):
		"""
		Generates master secret key
		"""
		return material[0:MSK_KEY_LENGTH];
	@staticmethod
	def generate_emsk(material):
		"""
		Generates extended master key
		"""
		return material[MSK_KEY_LENGTH:MSK_KEY_LENGTH + EMSK_KEY_LENGTH];

	@staticmethod
	def encrypt_ms_key(secret, authenticator, key):
		"""
		https://www.ietf.org/rfc/rfc2548.txt
		
		MS-MPPE-Send-Key

		   Description

		      The MS-MPPE-Send-Key Attribute contains a session key for use by
		      the Microsoft Point-to-Point Encryption Protocol (MPPE).  As the
		      name implies, this key is intended for encrypting packets sent
		      from the NAS to the remote host.  This Attribute is only included
		      in Access-Accept packets.

		   A summary of the MS-MPPE-Send-Key Attribute format is given below.
		   The fields are transmitted left to right.

		    0                   1                   2                   3
		    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		   |  Vendor-Type  | Vendor-Length |             Salt
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		                               String...
		   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

		   Vendor-Type
		      16 for MS-MPPE-Send-Key.

		   Vendor-Length
		      > 4

		   Salt
		      The Salt field is two octets in length and is used to ensure the
		      uniqueness of the keys used to encrypt each of the encrypted
		      attributes occurring in a given Access-Accept packet.  The most
		      significant bit (leftmost) of the Salt field MUST be set (1).  The
		      contents of each Salt field in a given Access-Accept packet MUST
		      be unique.

		   String
		      The plaintext String field consists of three logical sub-fields:
		      the Key-Length and Key sub-fields (both of which are required),
		      and the optional Padding sub-field.  The Key-Length sub-field is
		      one octet in length and contains the length of the unencrypted Key
		      sub-field.  The Key sub-field contains the actual encryption key.
		      If the combined length (in octets) of the unencrypted Key-Length
		      and Key sub-fields is not an even multiple of 16, then the Padding
		      sub-field MUST be present.  If it is present, the length of the
		      Padding sub-field is variable, between 1 and 15 octets.  The
		      String field MUST be encrypted as follows, prior to transmission:

		         Construct a plaintext version of the String field by concate-
		         nating the Key-Length and Key sub-fields.  If necessary, pad
		         the resulting string until its length (in octets) is an even
		         multiple of 16.  It is recommended that zero octets (0x00) be
		         used for padding.  Call this plaintext P.

		         Call the shared secret S, the pseudo-random 128-bit Request
		         Authenticator (from the corresponding Access-Request packet) R,
		         and the contents of the Salt field A.  Break P into 16 octet
		         chunks p(1), p(2)...p(i), where i = len(P)/16.  Call the
		         ciphertext blocks c(1), c(2)...c(i) and the final ciphertext C.
		         Intermediate values b(1), b(2)...c(i) are required.  Encryption
		         is performed in the following manner ('+' indicates
		         concatenation):

		      b(1) = MD5(S + R + A)    c(1) = p(1) xor b(1)   C = c(1)
		      b(2) = MD5(S + c(1))     c(2) = p(2) xor b(2)   C = C + c(2)
		                  .                      .
		                  .                      .
		                  .                      .
		      b(i) = MD5(S + c(i-1))   c(i) = p(i) xor b(i)   C = C + c(i)

		      The   resulting   encrypted   String   field    will    contain
		      c(1)+c(2)+...+c(i).

		   On receipt, the process is reversed to yield the plaintext String.

		   Implementation Notes
		      It is possible that the length of the key returned may be larger
		      than needed for the encryption scheme in use.  In this case, the
		      RADIUS client is responsible for performing any necessary
		      truncation.

		      This attribute MAY be used to pass a key from an external (e.g.,
		      EAP [15]) server to the RADIUS server.  In this case, it may be
		      impossible for the external server to correctly encrypt the key,
		      since the RADIUS shared secret might be unavailable.  The external
		      server SHOULD, however, return the attribute as defined above; the
		      Salt field SHOULD be zero-filled and padding of the String field
		      SHOULD be done.  When the RADIUS server receives the attribute
		      from the external server, it MUST correctly set the Salt field and
		      encrypt the String field before transmitting it to the RADIUS
		      client.  If the channel used to communicate the MS-MPPE-Send-Key
		      attribute is not secure from eavesdropping, the attribute MUST be
		      cryptographically protected.
		"""
		string = bytearray([len(key)]) + bytearray(key);
		if len(string) % 16 != 0x0:
			string = string + bytearray(([0x0] * (16 - len(string) % 16)));
		salt = bytearray(utils.Utils.generate_random(2));
		salt[0] = salt[0] | 0x80;
		
		md5 = MD5Digest();
		
		b1 = md5.digest(secret + authenticator + salt);
		c1 = bytearray([0] * len(b1));
		offset = 0;
		for i in range(0, len(b1)):
			c1[i] = string[offset + i] ^ b1[i];
		
		b2 = md5.digest(secret + c1);
		offset += len(b1);
		c2 = bytearray([0] * len(b2));
		for i in range(0, len(b2)):
			c2[i] = string[offset + i] ^ b2[i];
		
		b3 = md5.digest(secret + c2);
		offset += len(b2);
		c3 = bytearray([0] * len(b3));
		for i in range(0, len(b1)):
			c3[i] = string[offset + i] ^ b3[i];

		return salt + c1 + c2 + c3;
