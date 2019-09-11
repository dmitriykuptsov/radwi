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

from crypto.digest import SHA256Digest
from crypto.digest import SHA1Digest
from crypto.digest import HMACSHA256
from crypto import rsa;
from tls import tls;
from os import urandom

from binascii import hexlify;
from binascii import unhexlify;

MASTER_CONSTANT_STRING = "master secret";
KEY_EXPANSION_CONSTANTS_STRING = "key expansion";
CLIENT_FINISHED_CONSTANT_STRING = "client finished";
SERVER_FINISHED_CONSTANT_STRING = "server finished";

"""
Lengths of the keys
"""
CLIENT_WRITE_MAC_KEY_LENGTH    = 0x20;
SERVER_WRITE_MAC_KEY_LENGTH    = 0x20;
CLIENT_WRITE_CIPHER_KEY_LENGTH = 0x20;
SERVER_WRITE_CIPHER_KEY_LENGTH = 0x20;
CLIENT_WRITE_IV_LENGTH         = 0x10;
SERVER_WRITE_IV_LENGTH         = 0x10;
PRE_MASTER_SECRET_LENGTH       = 0x30;
MASTER_SECRET_LENGTH           = 0x30;

class Utils():
	"""
	Class which provides various helper methods such as
	computation of the master secret and key block. All
	methods in the class are static.
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
	def prf(secret, label, seed):
		SHA256digest = HMACSHA256();

	@staticmethod
	def compute_server_finished_message_mac(
		key, 
		sequence, 
		content_type, 
		version, 
		message):
		
		HMAC = HMACSHA256();
		# Finished message should have sequence number 0!
		length = len(message);
		pseudo_header = ([0] * (tls.TLS_SEQUENCE_NUMBER_LENGTH +
				tls.TLS_TYPE_FIELD_LENGTH + 
				tls.TLS_VERSION_FIELD_LENGTH + 
				tls.TLS_LENGTH_FIELD_LENGTH));

		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET]     = ((sequence >> 56) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 1] = ((sequence >> 48) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 2] = ((sequence >> 40) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 3] = ((sequence >> 32) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 4] = ((sequence >> 24) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 5] = ((sequence >> 16) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 6] = ((sequence >> 8) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 7] = ((sequence) & 0xFF);

		pseudo_header[tls.TLS_PSEUDO_HEADER_CONTENT_TYPE_OFFSET] = (tls.TLS_CONTENT_TYPE_HANDSHAKE & 0xFF);

		pseudo_header[tls.TLS_PSEUDO_HEADER_VERSION_OFFSET] = ((version >> 8) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_VERSION_OFFSET + 1] = ((version >> 8) & 0xFF);
		
		pseudo_header[tls.TLS_PSEUDO_HEADER_LENGTH_OFFSET] = ((length >> 8) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_LENGTH_OFFSET + 1] = (length & 0xFF);
		
		computed_hmac = HMAC.digest(key, bytearray(pseudo_header) + bytearray(message));

		return computed_hmac;

	@staticmethod
	def verify_mac(
		key, 
		sequence, 
		content_type, 
		version, 
		message,
		message_mac):
		
		HMAC = HMACSHA256();
		# Finished message should have sequence number 0!
		length = len(message);
		pseudo_header = ([0] * (tls.TLS_SEQUENCE_NUMBER_LENGTH +
				tls.TLS_TYPE_FIELD_LENGTH + 
				tls.TLS_VERSION_FIELD_LENGTH + 
				tls.TLS_LENGTH_FIELD_LENGTH));
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET]     = ((sequence >> 56) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 1] = ((sequence >> 48) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 2] = ((sequence >> 40) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 3] = ((sequence >> 32) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 4] = ((sequence >> 24) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 5] = ((sequence >> 16) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 6] = ((sequence >> 8) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET + 7] = ((sequence) & 0xFF);

		pseudo_header[tls.TLS_PSEUDO_HEADER_CONTENT_TYPE_OFFSET] = (content_type & 0xFF);

		pseudo_header[tls.TLS_PSEUDO_HEADER_VERSION_OFFSET] = ((version >> 8) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_VERSION_OFFSET + 1] = ((version >> 8) & 0xFF);
		
		pseudo_header[tls.TLS_PSEUDO_HEADER_LENGTH_OFFSET] = ((length >> 8) & 0xFF);
		pseudo_header[tls.TLS_PSEUDO_HEADER_LENGTH_OFFSET + 1] = (length & 0xFF);
		
		computed_hmac = HMAC.digest(key, bytearray(pseudo_header) + bytearray(message));

		return Utils.compare_bytearrays(computed_hmac, message_mac);

	@staticmethod
	def verify_client_finshed_message(master_secret, handshake_messages, verify_data_length):
		"""
		When this message will be sent:

		A Finished message is always sent immediately after a change
		cipher spec message to verify that the key exchange and
		authentication processes were successful.  It is essential that a
		change cipher spec message be received between the other handshake
		messages and the Finished message.

		Meaning of this message:

		The Finished message is the first one protected with the just
		negotiated algorithms, keys, and secrets.  Recipients of Finished
		messages MUST verify that the contents are correct.  Once a side
		has sent its Finished message and received and validated the
		Finished message from its peer, it may begin to send and receive
		application data over the connection.

		Structure of this message:

		struct {
		  opaque verify_data[verify_data_length];
		} Finished;

		verify_data
		 PRF(master_secret, finished_label, Hash(handshake_messages))
		    [0..verify_data_length-1];

		finished_label
		 For Finished messages sent by the client, the string
		 "client finished".  For Finished messages sent by the server,
		 the string "server finished".

		P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
		                     HMAC_hash(secret, A(2) + seed) +
		                     HMAC_hash(secret, A(3) + seed) + ...

		where + indicates concatenation.

		A() is defined as:

		A(0) = seed
		A(i) = HMAC_hash(secret, A(i-1))

		P_hash can be iterated as many times as necessary to produce the
		required quantity of data.  For example, if P_SHA256 is being used to
		create 80 bytes of data, it will have to be iterated three times
		(through A(3)), creating 96 bytes of output data; the last 16 bytes
		of the final iteration will then be discarded, leaving 80 bytes of
		output data.

		PRF(secret, label, seed) = P_<hash>(secret, label + seed)

		Hash denotes a Hash of the handshake messages.  For the PRF
		defined in Section 5, the Hash MUST be the Hash used as the basis
		for the PRF.  Any cipher suite which defines a different PRF MUST
		also define the Hash to use in the Finished computation.

		In previous versions of TLS, the verify_data was always 12 octets
		long.  In the current version of TLS, it depends on the cipher
		suite.  Any cipher suite which does not explicitly specify
		verify_data_length has a verify_data_length equal to 12.  This
		includes all existing cipher suites.  Note that this
		representation has the same encoding as with previous versions.
		Future cipher suites MAY specify other lengths but such length
		MUST be at least 12 bytes.
		"""
		HMAC = HMACSHA256();
		digest = SHA256Digest();
		handshake_messages_digest = digest.digest(bytearray(handshake_messages));
		
		seed = bytearray(str.encode(CLIENT_FINISHED_CONSTANT_STRING)) + handshake_messages_digest;
		A0 = seed;
		A1 = HMAC.digest(master_secret, A0);
		A2 = HMAC.digest(master_secret, A1);
		A3 = HMAC.digest(master_secret, A2);
		A4 = HMAC.digest(master_secret, A3);
		A5 = HMAC.digest(master_secret, A4);

		A = (HMAC.digest(master_secret, A1 + seed) + 
			HMAC.digest(master_secret, A2 + seed) + 
			HMAC.digest(master_secret, A3 + seed) +
			HMAC.digest(master_secret, A4 + seed) + 
			HMAC.digest(master_secret, A5 + seed));
		return A[0:verify_data_length];

	@staticmethod
	def verify_server_finshed_message(master_secret, handshake_messages, verify_data_length):
		"""
		When this message will be sent:

		A Finished message is always sent immediately after a change
		cipher spec message to verify that the key exchange and
		authentication processes were successful.  It is essential that a
		change cipher spec message be received between the other handshake
		messages and the Finished message.

		Meaning of this message:

		The Finished message is the first one protected with the just
		negotiated algorithms, keys, and secrets.  Recipients of Finished
		messages MUST verify that the contents are correct.  Once a side
		has sent its Finished message and received and validated the
		Finished message from its peer, it may begin to send and receive
		application data over the connection.

		Structure of this message:

		struct {
		  opaque verify_data[verify_data_length];
		} Finished;

		verify_data
		 PRF(master_secret, finished_label, Hash(handshake_messages))
		    [0..verify_data_length-1];

		finished_label
		 For Finished messages sent by the client, the string
		 "client finished".  For Finished messages sent by the server,
		 the string "server finished".

		P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
		                     HMAC_hash(secret, A(2) + seed) +
		                     HMAC_hash(secret, A(3) + seed) + ...

		where + indicates concatenation.

		A() is defined as:

		A(0) = seed
		A(i) = HMAC_hash(secret, A(i-1))

		P_hash can be iterated as many times as necessary to produce the
		required quantity of data.  For example, if P_SHA256 is being used to
		create 80 bytes of data, it will have to be iterated three times
		(through A(3)), creating 96 bytes of output data; the last 16 bytes
		of the final iteration will then be discarded, leaving 80 bytes of
		output data.

		PRF(secret, label, seed) = P_<hash>(secret, label + seed)

		Hash denotes a Hash of the handshake messages.  For the PRF
		defined in Section 5, the Hash MUST be the Hash used as the basis
		for the PRF.  Any cipher suite which defines a different PRF MUST
		also define the Hash to use in the Finished computation.

		In previous versions of TLS, the verify_data was always 12 octets
		long.  In the current version of TLS, it depends on the cipher
		suite.  Any cipher suite which does not explicitly specify
		verify_data_length has a verify_data_length equal to 12.  This
		includes all existing cipher suites.  Note that this
		representation has the same encoding as with previous versions.
		Future cipher suites MAY specify other lengths but such length
		MUST be at least 12 bytes.
		"""
		HMAC = HMACSHA256();
		digest = SHA256Digest();
		handshake_messages_digest = digest.digest(bytearray(handshake_messages));
		
		seed = bytearray(str.encode(SERVER_FINISHED_CONSTANT_STRING)) + handshake_messages_digest;
		A0 = seed;
		A1 = HMAC.digest(master_secret, A0);
		A2 = HMAC.digest(master_secret, A1);
		A3 = HMAC.digest(master_secret, A2);
		A4 = HMAC.digest(master_secret, A3);
		A5 = HMAC.digest(master_secret, A4);

		A = (HMAC.digest(master_secret, A1 + seed) + 
			HMAC.digest(master_secret, A2 + seed) + 
			HMAC.digest(master_secret, A3 + seed) +
			HMAC.digest(master_secret, A4 + seed) + 
			HMAC.digest(master_secret, A5 + seed));
		return A[0:verify_data_length];

	@staticmethod
	def compute_master_secret(pre_master_secret, client_random, server_random):
		"""
		Computes master secret based on the pre master secret, client random,
		server random and label


		P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
		                     HMAC_hash(secret, A(2) + seed) +
		                     HMAC_hash(secret, A(3) + seed) + ...

		where + indicates concatenation.

		A() is defined as:

		A(0) = seed
		A(i) = HMAC_hash(secret, A(i-1))

		P_hash can be iterated as many times as necessary to produce the
		required quantity of data.  For example, if P_SHA256 is being used to
		create 80 bytes of data, it will have to be iterated three times
		(through A(3)), creating 96 bytes of output data; the last 16 bytes
		of the final iteration will then be discarded, leaving 80 bytes of
		output data.

		TLS's PRF is created by applying P_hash to the secret as:

		PRF(secret, label, seed) = P_<hash>(secret, label + seed)

		"""

		HMAC = HMACSHA256();
		seed = bytearray(str.encode(MASTER_CONSTANT_STRING)) + client_random + server_random;
		A0 = seed;
		
		A1 =  HMAC.digest(pre_master_secret, A0);
		A2 =  HMAC.digest(pre_master_secret, A1);

		A = (HMAC.digest(pre_master_secret, A1 + seed) + 
			HMAC.digest(pre_master_secret, A2 + seed));
		return A[0:MASTER_SECRET_LENGTH];
	@staticmethod
	def compute_keying_material(master_secret, client_random, server_random):
		"""
		Computes keying material for AES_256_CBC_SHA256
		"""
		HMAC = HMACSHA256();
		seed = bytearray(str.encode(KEY_EXPANSION_CONSTANTS_STRING)) + server_random + client_random;
		A0 = seed;
		A1 = HMAC.digest(master_secret, A0);
		A2 = HMAC.digest(master_secret, A1);
		A3 = HMAC.digest(master_secret, A2);
		A4 = HMAC.digest(master_secret, A3);
		A5 = HMAC.digest(master_secret, A4);
		
		A = (HMAC.digest(master_secret, A1 + seed) + 
			HMAC.digest(master_secret, A2 + seed) + 
			HMAC.digest(master_secret, A3 + seed) +
			HMAC.digest(master_secret, A4 + seed) + 
			HMAC.digest(master_secret, A5 + seed));
		return A;

	@staticmethod
	def generate_client_write_mac_key(material):
		"""
		Generates client's mac write key from the given material
		"""
		return material[0:CLIENT_WRITE_MAC_KEY_LENGTH];
	@staticmethod
	def generate_server_write_mac_key(material):
		"""
		Generates server's write mac key from the given material
		"""
		return material[(CLIENT_WRITE_MAC_KEY_LENGTH):
						(CLIENT_WRITE_MAC_KEY_LENGTH + 
							SERVER_WRITE_MAC_KEY_LENGTH)];
	@staticmethod
	def generate_client_write_cipher_key(material):
		"""
		Generates client's write cipher key using provided material
		"""
		return material[(CLIENT_WRITE_MAC_KEY_LENGTH + 
						SERVER_WRITE_MAC_KEY_LENGTH):
						(CLIENT_WRITE_MAC_KEY_LENGTH + 
						SERVER_WRITE_MAC_KEY_LENGTH +
						CLIENT_WRITE_CIPHER_KEY_LENGTH)];
	@staticmethod
	def generate_server_write_cipher_key(material):
		"""
		Generates server's write cipher key from the given material
		"""
		return material[(CLIENT_WRITE_MAC_KEY_LENGTH + 
						SERVER_WRITE_MAC_KEY_LENGTH +
						CLIENT_WRITE_CIPHER_KEY_LENGTH):
						(CLIENT_WRITE_MAC_KEY_LENGTH + 
						SERVER_WRITE_MAC_KEY_LENGTH +
						CLIENT_WRITE_CIPHER_KEY_LENGTH +
						SERVER_WRITE_CIPHER_KEY_LENGTH)];
	@staticmethod
	def generate_client_write_iv(material):
		"""
		Generates client's intialization vector using provided keying material
		"""
		return material[(CLIENT_WRITE_MAC_KEY_LENGTH + 
						SERVER_WRITE_MAC_KEY_LENGTH +
						CLIENT_WRITE_CIPHER_KEY_LENGTH + 
						SERVER_WRITE_CIPHER_KEY_LENGTH):
						(CLIENT_WRITE_MAC_KEY_LENGTH + 
						SERVER_WRITE_MAC_KEY_LENGTH +
						CLIENT_WRITE_CIPHER_KEY_LENGTH +
						SERVER_WRITE_CIPHER_KEY_LENGTH + 
						CLIENT_WRITE_IV_LENGTH)];
	@staticmethod
	def generate_server_write_iv(material):
		"""
		Generates server's intialization vector using provided keying material
		"""
		return material[(CLIENT_WRITE_MAC_KEY_LENGTH + 
						SERVER_WRITE_MAC_KEY_LENGTH +
						CLIENT_WRITE_CIPHER_KEY_LENGTH + 
						SERVER_WRITE_CIPHER_KEY_LENGTH + 
						CLIENT_WRITE_IV_LENGTH):
						(CLIENT_WRITE_MAC_KEY_LENGTH + 
						SERVER_WRITE_MAC_KEY_LENGTH +
						CLIENT_WRITE_CIPHER_KEY_LENGTH +
						SERVER_WRITE_CIPHER_KEY_LENGTH + 
						CLIENT_WRITE_IV_LENGTH + 
						SERVER_WRITE_IV_LENGTH)];
	@staticmethod
	def generate_random(length):
		"""
		Generates random number of a given length
		"""
		return urandom(length);
	@staticmethod
	def derive_pre_master_secret(encrypted_pre_master_secret, expected_version, key):
		"""
		If RSA is being used for key agreement and authentication, the
		client generates a 48-byte premaster secret, encrypts it using the
		public key from the server's certificate, and sends the result in
		an encrypted premaster secret message.  This structure is a
		variant of the ClientKeyExchange message and is not a message in
		itself.

		Note: The version number in the PreMasterSecret is the version
		offered by the client in the ClientHello.client_version, not the
		version negotiated for the connection.  This feature is designed to
		prevent rollback attacks.  Unfortunately, some old implementations
		use the negotiated version instead, and therefore checking the
		version number may lead to failure to interoperate with such
		incorrect client implementations.

		Client implementations MUST always send the correct version number in
		PreMasterSecret.  If ClientHello.client_version is TLS 1.1 or higher,
		server implementations MUST check the version number as described in
		the note below.  If the version number is TLS 1.0 or earlier, server
		implementations SHOULD check the version number, but MAY have a
		configuration option to disable the check.  Note that if the check
		fails, the PreMasterSecret SHOULD be randomized as described below.

		Note: Attacks discovered by Bleichenbacher [BLEI] and Klima et al.
		[KPR03] can be used to attack a TLS server that reveals whether a
		particular message, when decrypted, is properly PKCS#1 formatted,
		contains a valid PreMasterSecret structure, or has the correct
		version number.


		As described by Klima [KPR03], these vulnerabilities can be avoided
		by treating incorrectly formatted message blocks and/or mismatched
		version numbers in a manner indistinguishable from correctly
		formatted RSA blocks.  In other words:

			1. Generate a string R of 46 random bytes

			2. Decrypt the message to recover the plaintext M

			3. If the PKCS#1 padding is not correct, or the length of message
			   M is not exactly 48 bytes:
					pre_master_secret = ClientHello.client_version || R
         	   else If ClientHello.client_version <= TLS 1.0, and version
					number check is explicitly disabled:
					pre_master_secret = M
				else:
					pre_master_secret = ClientHello.client_version || M[2..47]
		"""
		decryption_failed = False;
		pre_master_secret = None;
		try:
			pre_master_secret = rsa.RSACrypto().decrypt(encrypted_pre_master_secret, key);
		except Exception as e:
			print(str(e));
			decryption_failed = True;
		R = bytearray(Utils.generate_random(tls.TLS_PREMASTER_SECRET_LENGTH));
		current_version = ((pre_master_secret[0] << 8) & 0xFFFF) | (pre_master_secret[1] & 0xFF);
		if decryption_failed or current_version != expected_version:
			print("Invalid premaster decryption....");
			expected_version_bytes  = bytearray([0x0, 0x0]);
			expected_version_bytes[0] = ((expected_version >> 8) & 0xFF);
			expected_version_bytes[1] = (expected_version & 0xFF);
			return expected_version_bytes + R[2:tls.TLS_PREMASTER_SECRET_LENGTH];
		else:
			expected_version_bytes = bytearray([0] * 2);
			expected_version_bytes[0] = ((expected_version >> 8) & 0xFF);
			expected_version_bytes[1] = (expected_version & 0xFF);
			return expected_version_bytes + pre_master_secret[2:tls.TLS_PREMASTER_SECRET_LENGTH];
	@staticmethod
	def remove_null_bytes(string):
		a = []
		for i in range(0, len(string)):
			if string[i] != 0x0:
				a.append(string[i])
		return "".join(map(chr, a))
	
