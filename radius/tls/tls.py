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

from crypto.certs import X509v3Certificate;
from crypto.digest import MD5Digest;
from crypto.digest import SHA256Digest;
from crypto.digest import HMACSHA256;
from crypto.aes import AES;
from misc.compression import NullCompression;

# Base 16 encoding/decoding
import binascii;

# Timing 
from time import time;

TLS_PROTOCOL_VERSION                       = 0x0303;

# Cipher suits
TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA         = 0xc014;
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA       = 0xc00a;
TLS_DHE_RSA_WITH_AES_256_CBC_SHA           = 0x0039;
TLS_DHE_DSS_WITH_AES_256_CBC_SHA           = 0x0038;
TLS_DH_RSA_WITH_AES_256_CBC_SHA            = 0x0037;
TLS_DH_DSS_WITH_AES_256_CBC_SHA            = 0x0036;
TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA      = 0x0088;
TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA      = 0x0087;
TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA       = 0x0086;
TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA       = 0x0085;
TLS_ECDH_RSA_WITH_AES_256_CBC_SHA          = 0xc00f;
TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA        = 0xc005;
TLS_RSA_WITH_AES_256_CBC_SHA               = 0x0035;
TLS_RSA_WITH_AES_256_CBC_SHA256            = 0x003d;
TLS_RSA_WITH_CAMELLIA_256_CBC_SHA          = 0x0084;
TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA         = 0xc013;
TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA       = 0xc009;
TLS_DHE_RSA_WITH_AES_128_CBC_SHA           = 0x0033;
TLS_DHE_DSS_WITH_AES_128_CBC_SHA           = 0x0032;
TLS_DH_RSA_WITH_AES_128_CBC_SHA            = 0x0031;
TLS_DH_DSS_WITH_AES_128_CBC_SHA            = 0x0030;
TLS_DHE_RSA_WITH_SEED_CBC_SHA              = 0x009a;
TLS_DHE_DSS_WITH_SEED_CBC_SHA              = 0x0099;
TLS_DH_RSA_WITH_SEED_CBC_SHA               = 0x0098;
TLS_DH_DSS_WITH_SEED_CBC_SHA               = 0x0097;
TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA      = 0x0045;
TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA      = 0x0044;
TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA       = 0x0043;
TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA       = 0x0042;
TLS_ECDH_RSA_WITH_AES_128_CBC_SHA          = 0xc00e;
TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA        = 0xc004;
TLS_RSA_WITH_AES_128_CBC_SHA               = 0x002f;
TLS_RSA_WITH_SEED_CBC_SHA                  = 0x0096;
TLS_RSA_WITH_CAMELLIA_128_CBC_SHA          = 0x0041;
TLS_RSA_WITH_IDEA_CBC_SHA                  = 0x0007;
TLS_ECDHE_RSA_WITH_RC4_128_SHA             = 0xc011;
TLS_ECDHE_ECDSA_WITH_RC4_128_SHA           = 0xc007;
TLS_ECDH_RSA_WITH_RC4_128_SHA              = 0xc00c;
TLS_ECDH_ECDSA_WITH_RC4_128_SHA            = 0xc002;
TLS_RSA_WITH_RC4_128_SHA                   = 0x0005;
TLS_RSA_WITH_RC4_128_MD5                   = 0x0004;
TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA        = 0xc012;
TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA      = 0xc008;
TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA          = 0x0016;
TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA          = 0x0013;
TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA           = 0x0010;
TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA           = 0x000d;
TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA         = 0xc00d;
TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA       = 0xc003;
TLS_RSA_WITH_3DES_EDE_CBC_SHA              = 0x000a;
TLS_DHE_RSA_WITH_DES_CBC_SHA               = 0x0015;
TLS_DHE_DSS_WITH_DES_CBC_SHA               = 0x0012;
TLS_DH_RSA_WITH_DES_CBC_SHA                = 0x000f;
TLS_DH_DSS_WITH_DES_CBC_SHA                = 0x000c;
TLS_RSA_WITH_DES_CBC_SHA                   = 0x0009;
TLS_EMPTY_RENEGOTIATION_INFO_SCSV          = 0x00ff;

# Compression methods
TLS_COMPRESSION_METHOD                     = 0x0;

# Handshake type 
HANDSHAKE_TYPE_CLIENT_HELLO                = 0x1;
HANDSHAKE_TYPE_SERVER_HELLO                = 0x2;
HANDSHAKE_TYPE_CERTIFICATE                 = 0x0b;
HANDSHAKE_TYPE_CERTIFICATE_VERIFY          = 0x0f;
HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE         = 0x0c;
HANDSHAKE_TYPE_CERTIFICATE_REQUEST         = 0xd;
HANDSHAKE_TYPE_SERVER_HELLO_DONE           = 0xe;
HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE         = 0x10;
HANDSHAKE_TYPE_CHANGE_CIPHER_SPEC          = 0x14;
HANDSHAKE_TYPE_ENCRYPTED_MESSAGE           = 0x16;
HANDSHAKE_TYPE_FINISHED_MESSAGE            = 0x14;
TLS_RECORD_LAYER_HEADER_LENGTH             = 0x5;

# Fixed packet lengths
HANDSHAKE_TYPE_LENGTH                      = 0x1;
HANDSHAKE_LENGTH_LENGTH                    = 0x3;
HANDSHAKE_TLS_VERSION_LENGTH               = 0x2;
HANDSHAKE_SERVER_HELLO_RANDOM_LENGTH       = 0x20;
HANDSHAKE_SERVER_HELLO_SESSION_ID_LENGTH   = 0x1;
HANDSHAKE_SERVER_HELLO_CIPHER_SUIT_LENGTH  = 0x2;
HANDSHAKE_SERVER_HELLO_COMPRESSION_METHOD_LENGTH = 0x1;
HANDSHAKE_SERVER_HELLO_EXTENSIONS_LENGTH         = 0x2;
HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH         = 0x1;
HANDSHAKE_CLIENT_HELLO_EXTENSION_TYPE_LENGTH     = 0x2;
HANDSHAKE_CLIENT_HELLO_EXTENSION_LENGTH_LENGTH   = 0x2;
HANDSHAKE_SERVER_HELLO_EXTENSION_TYPE_LENGTH     = 0x2;
HANDSHAKE_SERVER_HELLO_EXTENSION_LENGTH_LENGTH   = 0x2;
TLS_HANDSHAKE_CIPHER_SUITS_LENGTH_LENGTH   = 0x2;
TLS_HANDSHAKE_COMPRESSION_LENGTH_LENGTH    = 0x1;
TLS_HANDSHAKE_EXTENSION_LENGTH_LENGTH      = 0x2;

HANDSHAKE_CLIENT_HELLO_RANDOM_LENGTH       = 0x20;

# TLS packet types
TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC        = 0x14;
TLS_CONTENT_TYPE_ALERT                     = 0x15;
TLS_CONTENT_TYPE_HANDSHAKE                 = 0x16;
TLS_CONTENT_TYPE_APPLICATION_DATA          = 0x17;

# Offsets
TLS_CONTENT_TYPE_OFFSET                    = 0x0;
TLS_VERSION_OFFSET                         = 0x1;
TLS_LENGTH_OFFSET                          = 0x3;
TLS_PROTOCOL_HANDSHAKE_TYPE_OFFSET         = 0x0;
TLS_PROTOCOL_LENGTH_OFFSET                 = 0x1;

# Extensions offsets
TLS_EXTENSION_TYPE_OFFSET                  = 0x0;
TLS_EXTENSION_LENGTH_OFFSET                = 0x2;

# Handshake protocol server hello
TLS_HANDSHAKE_TYPE_OFFSET                  = 0x0;
TLS_HANDSHAKE_LENGTH_OFFSET                = 0x1;
TLS_HANDSHAKE_VERSION_OFFSET               = 0x4;
TLS_HANDSHAKE_RANDOM_OFFSET                = 0x6;
TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET     = 0x26;
TLS_HANDSHAKE_CIPHER_SUIT_OFFSET           = 0x27;
TLS_HANDSHAKE_COMPRESSION_METHOD_OFFSET    = 0x29;
TLS_HANDSHAKE_EXTENSIONS_LENGTH_OFFSET     = 0x2A;
TLS_HANDSHAKE_EXTENSIONS_OFFSET            = 0x2C;

# Extension types
TLS_RENIGOTIATION_INFO_EXTENSION_TYPE      = 0xFF01;
TLS_EC_POINTS_FORMATS_EXTENSION_TYPE       = 0x000b;
TLS_HEARTBEAT_EXTENSION_TYPE               = 0x000f;


TLS_CONNECTION_END_SERVER                  = 0x1;
TLS_PRF_ALGORITHM_SHA256                   = 0x1;
TLS_PRF_ALGORITHM_SHA1                     = 0x2;
TLS_PRF_ALGORITHM_MD5                      = 0x3;
TLS_BULK_ENCRYPTION_ALGORITHM_AES_CBC      = 0x1;
TLS_MAC_ALGORITHM_SHA256                   = 0x1;
TLS_COMPRESSION_ALGORITHM_NULL             = 0x0;

TLS_CHANGE_CIPHER_SPEC_MESSAGE             = 0x1;

TLS_SESSION_TIMEOUT                        = 0x5; # 5 seconds

TLS_SEQUENCE_NUMBER_LENGTH                 = 0x8;
TLS_VERSION_FIELD_LENGTH                   = 0x2;
TLS_TYPE_FIELD_LENGTH                      = 0x1;
TLS_LENGTH_FIELD_LENGTH                    = 0x2;

TLS_PSEUDO_HEADER_SEQUENCE_NUMBER_OFFSET   = 0x0;
TLS_PSEUDO_HEADER_CONTENT_TYPE_OFFSET      = 0x8;
TLS_PSEUDO_HEADER_VERSION_OFFSET           = 0x9;
TLS_PSEUDO_HEADER_LENGTH_OFFSET            = 0xb;



class AlgorithmFactory():
	"""
	Algorithm factory class.
	"""
	@staticmethod
	def get_prf_algorithm(alg):
		"""
		Creates an instance of pseudo random algorithm based on 
		supplied algorithm identifier
		"""
		if alg == TLS_PRF_ALGORITHM_SHA256:
			return SHA256Digest();
		else:
			raise Exception("Algorithm is not supported");
	@staticmethod
	def get_mac_algorithm(alg):
		"""
		Creates an instance of message authentication 
		algorithm
		"""
		if alg == TLS_MAC_ALGORITHM_SHA256:
			return HMACSHA256();
		else:
			raise Exception("Algorithm is not supported");
	@staticmethod
	def get_cipher(alg, key, iv):
		"""
		Creates an instance of block cipher
		""" 
		if alg == TLS_BULK_ENCRYPTION_ALGORITHM_AES_CBC:
			return AES(AES.MODE_CBC, key, iv);
		else:
			raise Exception("Algorithm is not supported");
	@staticmethod
	def get_compression(alg):
		"""
		Creates an instance of NULL compression algorithm
		"""
		if alg == TLS_COMPRESSION_ALGORITHM_NULL:
			return NullCompression();
		else:
			raise Exception("Algorithm is not supported");
class TLSState():
	"""
	Represents TLS state
	"""
	def __init__(self, calling_station_id):
		# Address of the peer
		self.calling_station_id = calling_station_id;

		# Supported algorithms
		self.connection_end = TLS_CONNECTION_END_SERVER;
		self.prf_algorithm = TLS_PRF_ALGORITHM_SHA256;
		self.bulk_encryption_algorithm = TLS_BULK_ENCRYPTION_ALGORITHM_AES_CBC;
		self.mac_algorithm = TLS_MAC_ALGORITHM_SHA256;
		self.compression_algorithm = TLS_COMPRESSION_ALGORITHM_NULL;
		
		# Sequene progress
		self.sequence = 0x0;

		# State machine states
		self.client_hello_received = False;
		self.server_hello_sent = False;
		self.server_certificate_sent = False;
		self.server_hello_done_sent = False;
		self.client_key_exchange_received = False;
		self.client_cipher_spec_changed_received = False;
		self.client_finished_message_received = False;
		self.server_cipher_spec_changed_sent = False;
		self.server_finished_message_sent = False;

		self.is_encrypted = False;

		# Cryptographic material
		self.master_secret = None;
		self.client_random = None;
		self.server_random = None;
		self.client_write_mac_key = None;
		self.client_write_iv = None;
		self.client_write_cipher_key = None;
		self.server_write_mac_key = None;
		self.server_write_iv = None;
		self.server_write_cipher_key = None;

		#Sequece numbers
		self.client_sequence_number = 0x0;
		self.server_sequence_number = 0x0;

		self.last_tx_rx_packet = int(time());
	def get_connection_end(self):
		return self.connection_end;
	def set_connection_end(self, type):
		self.connection_end = type;
	def get_prf_algorithm(self):
		return self.prf_algorithm;
	def set_prf_algorithm(self, alg):
		self.prf_algorithm = alg;
	def get_bulk_encryption_algorithm(self):
		return self.bulk_encryption_algorithm;
	def set_bulk_encryption_algorithm(self, alg):
		self.bulk_encryption_algorithm = alg;
	def get_mac_algorithm(self):
		return self.mac_algorithm;
	def set_mac_algorithm(self, alg):
		self.mac_algorithm = alg;
	def get_compression_algorithm(self):
		return self.compression_algorithm;
	def set_compression_algorithm(self, compression_alg):
		self.compression_algorithm = compression_alg;
	def get_master_secret(self):
		return self.master_secret;
	def set_master_secret(self, secret):
		self.master_secret = secret;
	def get_client_random(self):
		return self.client_random;
	def set_client_random(self, random):
		self.client_random = random;
	def get_server_random(self):
		return self.server_random;
	def set_server_random(self, random):
		self.server_random = random;
	def get_is_encrypted(self):
		return self.is_encrypted;
	def set_is_encrypted(self, encrypted):
		self.is_encrypted = encrypted;
	def get_client_hello_received(self):
		return self.client_hello_received;
	def set_client_hello_received(self, client_hello_received):
		self.client_hello_received = client_hello_received;
	def get_server_hello_sent(self):
		return self.server_hello_sent;
	def set_server_hello_sent(self, server_hello_sent):
		self.server_hello_sent = server_hello_sent;
	def get_server_certificate_sent(self):
		return self.server_certificate_sent;
	def set_server_certificate_sent(self, server_certificate_sent):
		self.server_certificate_sent = server_certificate_sent;
	def get_server_hello_done_sent(self):
		return self.server_hello_done_sent;
	def set_server_hello_done_sent(self, server_hello_done_sent):
		self.server_hello_done_sent = server_hello_done_sent;
	def get_client_key_exchange_received(self):
		return self.client_key_exchange_received;
	def set_client_key_exchange_received(self, client_key_exchange_received):
		self.client_key_exchange_received = client_key_exchange_received;
	def get_client_cipher_spec_changed_received(self):
		return self.client_cipher_spec_changed_received;
	def set_client_cipher_spec_changed_received(self, client_cipher_spec_changed_received):
		self.client_cipher_spec_changed_received = client_cipher_spec_changed_received;
	def get_client_finished_message_received(self):
		return self.client_finished_message_received;
	def set_client_finished_message_received(self, client_finished_message_received):
		self.client_finished_message_received = client_finished_message_received;
	def get_server_cipher_spec_changed_sent(self):
		return self.server_cipher_spec_changed_sent;
	def set_server_cipher_spec_changed_sent(self, server_cipher_spec_changed_sent):
		self.server_cipher_spec_changed_sent = server_cipher_spec_changed_sent;
	def get_server_finished_message_sent(self):
		return self.server_finished_message_sent;
	def set_server_finished_message_sent(self, server_finished_message_sent):
		self.server_finished_message_sent = server_finished_message_sent;
	def set_client_write_mac_key(self, key):
		self.client_write_mac_key = key;
	def get_client_write_mac_key(self):
		return self.client_write_mac_key;
	def set_client_write_iv(self, iv):
		self.client_write_iv = iv;
	def get_client_write_iv(self):
		return self.client_write_iv;
	def set_client_write_cipher_key(self, key):
		self.client_write_cipher_key = key;
	def get_client_write_cipher_key(self):
		return self.client_write_cipher_key;
	def set_server_write_mac_key(self, key):
		self.server_write_mac_key = key;
	def get_server_write_mac_key(self):
		return self.server_write_mac_key;
	def set_server_write_iv(self, iv):
		self.server_write_iv = iv;
	def get_server_write_iv(self, iv):
		return self.server_write_iv;
	def set_server_write_cipher_key(self, key):
		self.server_write_cipher_key = key;
	def get_server_write_cipher_key(self):
		return self.server_write_cipher_key;
	def update_last_tx_rx_time(self):
		self.last_tx_rx_packet = int(time());
	def get_last_tx_rx_time(self):
		return self.last_tx_rx_packet;
	def get_calling_station_id(self):
		return self.calling_station_id;
	def get_client_sequence_number(self):
		return self.client_sequence_number;
	def get_server_sequence_number(self):
		return self.server_sequence_number;
	def increment_client_sequence_number(self):
		self.client_sequence_number += 1;
	def increment_server_sequence_number(self):
		self.server_sequence_number += 1;
class TLSStateMachine():
	"""
	Basic state machine structure
	"""
	def __init__(self):
		self.state = dict();
	def get_connection_id(self, id):
		"""
		Internal method, which produces the actual key for dictionary
		"""
		return binascii.hexlify(SHA256Digest().digest(id));
	def init_state(self, calling_station_id):
		"""
		Initializes the state
		"""
		conn_id = self.get_connection_id(calling_station_id);
		self.state[conn_id] = TLSState(calling_station_id);
	def get_state(self, calling_station_id):
		"""
		Gets state by calling station id
		"""
		conn_id = self.get_connection_id(calling_station_id);
		try:
			return self.state[conn_id];
		except:
			return None
	def get_states(self):
		"""
		Gets all states as an array
		"""
		tls_states = [];
		for key in self.state.keys():
			tls_states.append(self.state[key]);
		return tls_states;
	def remove_state(self, calling_station_id):
		"""
		Invalidates the TLS state (removes it from the database)
		"""
		conn_id = self.get_connection_id(calling_station_id);
		self.state[conn_id] = None;
class TLSPacket():
	"""
	TLS packet structure. Basically, it contains set of TLS Records 
	"""
	# https://tools.ietf.org/html/rfc5246#section-6
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = [];
	def get_records(self):
		"""
		Parses TLS packet and extracts TLS record layers
		"""
		has_more_records = True;
		offset = 0;
		records = [];
		while has_more_records:
			"""
			Iterates over all record layers and pushes them to the array
			"""
			if (self.buffer[offset + TLS_CONTENT_TYPE_OFFSET] == TLS_CONTENT_TYPE_HANDSHAKE or
				self.buffer[offset + TLS_CONTENT_TYPE_OFFSET] == TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC or
				self.buffer[offset + TLS_CONTENT_TYPE_OFFSET] == TLS_CONTENT_TYPE_ALERT or 
				self.buffer[offset + TLS_CONTENT_TYPE_OFFSET] == TLS_CONTENT_TYPE_APPLICATION_DATA):
				record_length = ((self.buffer[offset + TLS_LENGTH_OFFSET] << 8) | self.buffer[offset + TLS_LENGTH_OFFSET + 1]);
				records.append(TLSRecordLayer(self.buffer[offset:
					offset + TLS_RECORD_LAYER_HEADER_LENGTH + record_length]));
				offset = offset + record_length + TLS_RECORD_LAYER_HEADER_LENGTH;
				if offset == len(self.buffer):
					has_more_records = False;
			else: 
				raise ValueError("Undefined TLS record");
		return records;
	def add_record(self, record):
		"""
		Adds new record to the packet
		"""
		offset = len(self.buffer);
		boundary = offset + len(record.get_bytes());
		self.buffer[offset:boundary] = record.get_bytes();
	def get_bytes(self):
		"""
		Gets raw packet bytes
		"""
		return self.buffer;
class TLSHandshakeProtocol():
	def __init__(self, buffer):
		self.buffer = buffer;
	def get_bytes(self):
		return self.buffer;
	def get_type(self):
		return self.buffer[TLS_HANDSHAKE_TYPE_OFFSET];
	def set_type(self, type):
		self.buffer[TLS_HANDSHAKE_TYPE_OFFSET] = type;
	def get_length(self):
		return ((self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET] << 16) | 
				self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 1] << 8 |
				self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 2]);
	def set_length(self, length):
		self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET] = ((length >> 16) & 0xFF);
		self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 1]  = ((length >> 8) & 0xFF);
		self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 2]  = (length & 0xFF);
	def get_version(self):
		return ((
			self.buffer[TLS_HANDSHAKE_VERSION_OFFSET] << 8) | 
			self.buffer[TLS_HANDSHAKE_VERSION_OFFSET + 1]
			);

HANDSHAKE_TYPE_FINISHED_MESSAGE = 0x14;
FINISHED_MESSAGE_VERIFY_DATA_OFFSET = 0x4;
FINISHED_MESSAGE_VERIFY_DATA_LENGTH = 0x0c;
FINISHED_MESSAGE_HMAC_LENGTH = 0x20;
HMAC_LENGTH = 0x20;

class FinishedMessageProtocol(TLSHandshakeProtocol):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = ([0] * (
				TLS_HANDSHAKE_TYPE_FIELD_LENGTH + 
				TLS_HANDSHAKE_LENGTH_FIELD_LENGTH
				));
			self.buffer[TLS_HANDSHAKE_TYPE_OFFSET] = HANDSHAKE_TYPE_FINISHED_MESSAGE;
	def get_verify_data(self):
		offset = FINISHED_MESSAGE_VERIFY_DATA_OFFSET;
		length = self.get_length();
		return self.buffer[offset:offset + length];
	def set_verify_data(self, verify_data):
		self.set_length(len(verify_data));
		length = self.get_length();
		offset = FINISHED_MESSAGE_VERIFY_DATA_OFFSET;
		self.buffer[offset:offset + length] = verify_data;
		

TLS_CLIENT_KEY_EXCHANGE_ENCRYPTED_PREMASTER_OFFSET = 0x4;
TLS_PREMASTER_SECRET_LENGTH = 0x30;
TLS_ENCRYPTED_PREMASTER_LENGTH_LENGTH = 0x2;

class TLSClientKeyExchangeProtocol(TLSHandshakeProtocol):
	def __init__(self, buffer):
		self.buffer = buffer;
	def get_encrypted_premaster_secret(self):
		"""
		Implementation note: Public-key-encrypted data is represented as an
		opaque vector <0..2^16-1> (see Section 4.7).  Thus, the RSA-encrypted
		PreMasterSecret in a ClientKeyExchange is preceded by two length
		bytes.  These bytes are redundant in the case of RSA because the
		EncryptedPreMasterSecret is the only data in the ClientKeyExchange
		and its length can therefore be unambiguously determined.  The SSLv3
		specification was not clear about the encoding of public-key-
		encrypted data, and therefore many SSLv3 implementations do not
		include the length bytes -- they encode the RSA-encrypted data
		directly in the ClientKeyExchange message.
		"""
		length = self.get_length();
		offset = TLS_CLIENT_KEY_EXCHANGE_ENCRYPTED_PREMASTER_OFFSET;
		return self.buffer[offset + TLS_ENCRYPTED_PREMASTER_LENGTH_LENGTH:offset + length];

TLS_SERVER_KEY_EXCHANGE_ENCRYPTED_PREMASTER_OFFSET = 0x4;
class TLSServerKeyExchangeProtocol(TLSHandshakeProtocol):
	def __init__(self, buffer):
		self.buffer = buffer;
	def get_encrypted_premaster_secret(self):
		length = self.get_length();
		offset = TLS_SERVER_KEY_EXCHANGE_ENCRYPTED_PREMASTER_OFFSET;
		return self.buffer[offset:offset + length];

TLS_CHANGE_CIPHER_SPEC_MESSAGE_OFFSET = 0x5;
TLS_CHANGE_CIPHER_SPEC_MESSAGE_LENGTH = 0x1;
TLS_CHANGE_CIPHER_SPEC_MESSAGE        = 0x1;
class TLSChangeCipherSpecProtocol(TLSHandshakeProtocol):
	def __init__(self, buffer = None):
		self.buffer = buffer;
	def get_message(self):
		length = self.get_length();
		offset = TLS_CHANGE_CIPHER_SPEC_MESSAGE_OFFSET;
		return self.buffer[offset:offset + length];
	def set_message(self, message):
		length = len(message);
		offset = TLS_CHANGE_CIPHER_SPEC_MESSAGE_OFFSET;
		self.buffer[offset:offset + length] = message;

TLS_CHANGE_ENCRYPTED_MESSAGE_OFFSET = 0x5;

class TLSEncryptedMessageProtocol(TLSHandshakeProtocol):
	def __init__(self, buffer):
		self.buffer = buffer;
	def get_encrypted_message(self):
		length = self.get_length();
		offset = TLS_CHANGE_ENCRYPTED_MESSAGE_OFFSET;
		return self.buffer[offset:offset + length];
class TLSClientHelloProtocol(TLSHandshakeProtocol):
	"""
	TLS client hello protocol
	"""
	def __init__(self, buffer = None):
		self.buffer = buffer;
	def get_random(self):
		return self.buffer[TLS_HANDSHAKE_RANDOM_OFFSET:TLS_HANDSHAKE_RANDOM_OFFSET + HANDSHAKE_CLIENT_HELLO_RANDOM_LENGTH];
	def get_session_id(self):
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		if session_id_length == 0x0:
			return 0x0;
		return self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET + 
				HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH:
				TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET + 
				HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH +
				session_id_length];
	def get_cipher_suits_length(self):
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		cipher_suits_length = ((self.buffer[
							TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET + 
							HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH +
							session_id_length] << 8) |
							(self.buffer[
							TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET + 
							HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH +
							session_id_length + 1]));
		return cipher_suits_length;
	def get_cipher_suits(self):
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		cipher_suits_length = self.get_cipher_suits_length();
		return self.buffer[
						TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET +  
						HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH +
						session_id_length +
						TLS_HANDSHAKE_CIPHER_SUITS_LENGTH_LENGTH:
						TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET + 
						HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH + 
						session_id_length + 
						TLS_HANDSHAKE_CIPHER_SUITS_LENGTH_LENGTH +
						cipher_suits_length];
	def get_compression_methods_length(self):
		cipher_suits_length = self.get_cipher_suits_length();
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		offset = (TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET + 
						session_id_length + 
						HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH + 
						TLS_HANDSHAKE_CIPHER_SUITS_LENGTH_LENGTH +
						cipher_suits_length);
		return self.buffer[offset];
	def get_compressions(self):
		cipher_suits_length = self.get_cipher_suits_length();
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		compression_methods_length = self.get_compression_methods_length();
		offset = (TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET + 
						session_id_length + 
						HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH + 
						TLS_HANDSHAKE_CIPHER_SUITS_LENGTH_LENGTH +
						cipher_suits_length + 
						TLS_HANDSHAKE_COMPRESSION_LENGTH_LENGTH);
		return self.buffer[offset:offset + compression_methods_length];
	def get_extensions_length(self):
		cipher_suits_length = self.get_cipher_suits_length();
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		compression_methods_length = self.get_compression_methods_length();
		offset = (TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET + 
						session_id_length + 
						HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH + 
						TLS_HANDSHAKE_CIPHER_SUITS_LENGTH_LENGTH +
						cipher_suits_length + 
						TLS_HANDSHAKE_COMPRESSION_LENGTH_LENGTH + 
						compression_methods_length);
		return ((self.buffer[offset] << 8) | self.buffer[offset + 1]);
	def get_extensions(self):
		cipher_suits_length = self.get_cipher_suits_length();
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		compression_methods_length = self.get_compression_methods_length();
		offset = (TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET + 
						session_id_length + 
						HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH + 
						TLS_HANDSHAKE_CIPHER_SUITS_LENGTH_LENGTH +
						cipher_suits_length + 
						TLS_HANDSHAKE_COMPRESSION_LENGTH_LENGTH + 
						compression_methods_length +
						TLS_HANDSHAKE_EXTENSION_LENGTH_LENGTH);
		extensions_length = self.get_extensions_length();
		return self.buffer[offset:offset + extensions_length];
class TLSServerHelloProtocol(TLSHandshakeProtocol):
	"""
	Server hello protocol
	The server currently supports only TLS_RSA_WITH_AES_256_CBC_SHA256 security suit
	and does not support compression, meaning that all the data will be sent un-
	compressed. Accodring to RFC TLS_RSA_WITH_AES_128_CBC_SHA is mandatory.
	"""
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = ([0]*(
							HANDSHAKE_TYPE_LENGTH +
							HANDSHAKE_LENGTH_LENGTH +
							HANDSHAKE_TLS_VERSION_LENGTH +
							HANDSHAKE_SERVER_HELLO_RANDOM_LENGTH +
							HANDSHAKE_SERVER_HELLO_SESSION_ID_LENGTH +
							HANDSHAKE_SERVER_HELLO_CIPHER_SUIT_LENGTH +
							HANDSHAKE_SERVER_HELLO_COMPRESSION_METHOD_LENGTH +
							HANDSHAKE_SERVER_HELLO_EXTENSIONS_LENGTH
							));
			length = (len(self.buffer) - HANDSHAKE_TYPE_LENGTH - HANDSHAKE_LENGTH_LENGTH);
			self.buffer[TLS_HANDSHAKE_TYPE_OFFSET] = HANDSHAKE_TYPE_SERVER_HELLO;
			self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET] = (length >> 16) & 0xFF;
			self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 1] = (length >> 8) & 0xFF;
			self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 2] = (length) & 0xFF;
			self.buffer[TLS_HANDSHAKE_VERSION_OFFSET] = (TLS_PROTOCOL_VERSION >> 8) & 0xFF;
			self.buffer[TLS_HANDSHAKE_VERSION_OFFSET + 1] = TLS_PROTOCOL_VERSION & 0xFF;
			self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET] = 0x0;
			self.buffer[TLS_HANDSHAKE_CIPHER_SUIT_OFFSET] = (TLS_RSA_WITH_AES_256_CBC_SHA256 >> 8) & 0xFF; # This is the only cipher suit which will be supported for now
			self.buffer[TLS_HANDSHAKE_CIPHER_SUIT_OFFSET + 1] = TLS_RSA_WITH_AES_256_CBC_SHA256 & 0xFF; # This is the only cipher suit which will be supported for now
			self.buffer[TLS_HANDSHAKE_COMPRESSION_METHOD_OFFSET] = TLS_COMPRESSION_ALGORITHM_NULL;
			self.buffer[TLS_HANDSHAKE_EXTENSIONS_LENGTH_OFFSET] = 0x0;
	def set_version(self, version):
		self.buffer[TLS_HANDSHAKE_VERSION_OFFSET] = (version << 8) & 0xFF;
		self.buffer[TLS_HANDSHAKE_VERSION_OFFSET + 1] = version & 0xFF;
	def set_random(self, random):
		if len(random) != HANDSHAKE_SERVER_HELLO_RANDOM_LENGTH:
			raise Exception("Invalid random value");
		self.buffer[TLS_HANDSHAKE_RANDOM_OFFSET:TLS_HANDSHAKE_RANDOM_OFFSET + 
					HANDSHAKE_SERVER_HELLO_RANDOM_LENGTH] = random;
	def get_random(self):
		return self.buffer[TLS_HANDSHAKE_RANDOM_OFFSET:TLS_HANDSHAKE_RANDOM_OFFSET + 
							HANDSHAKE_SERVER_HELLO_RANDOM_LENGTH]
	def get_session_id(self):
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		if session_id_length == 0x0:
			return 0x0;
		return self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET + 
				HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH:
				TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET + 
				HANDSHAKE_CLIENT_HELLO_SESSION_ID_LENGTH +
				session_id_length];
	def set_cipher_suit(self, cipher_suit):
		"""
		Sets TLS cipher suit field to a given value
		"""
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		offset = TLS_HANDSHAKE_CIPHER_SUIT_OFFSET + session_id_length;
		self.buffer[offset] = (cipher_suit >> 8) & 0xFF;
		self.buffer[offset + 1] = cipher_suit & 0xFF;
	def get_cipher_suit(self):
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		offset = TLS_HANDSHAKE_CIPHER_SUIT_OFFSET + session_id_length;
		return (self.buffer[offset] << 8) | self.buffer[offset + 1];
	def get_compression(self):
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		offset = TLS_HANDSHAKE_COMPRESSION_METHOD_OFFSET + session_id_length;
		return self.buffer[offset]
	def get_extensions_length(self):
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		offset = TLS_HANDSHAKE_EXTENSIONS_LENGTH_OFFSET + session_id_length;
		return (self.buffer[offset] << 8) | self.buffer[offset + 1];
	def get_extensions(self):
		length = self.get_length() + HANDSHAKE_TYPE_LENGTH + HANDSHAKE_LENGTH_LENGTH;
		session_id_length = self.buffer[TLS_HANDSHAKE_SESSION_ID_LENGTH_OFFSET];
		offset = TLS_HANDSHAKE_EXTENSIONS_OFFSET + session_id_length;
		extensions = [];
		while True:
			ext_length = ((
						self.buffer[offset + TLS_EXTENSION_LENGTH_OFFSET] << 8) | 
						self.buffer[offset + TLS_EXTENSION_LENGTH_OFFSET + 1]);
			ext_boundary = offset + (ext_length + 
				HANDSHAKE_SERVER_HELLO_EXTENSION_LENGTH_LENGTH + 
				HANDSHAKE_SERVER_HELLO_EXTENSION_TYPE_LENGTH);
			if TLS_RENIGOTIATION_INFO_EXTENSION_TYPE == ((self.buffer[offset + TLS_EXTENSION_TYPE_OFFSET] << 8) | self.buffer[offset + TLS_EXTENSION_TYPE_OFFSET + 1]):
				extensions.append(TLSRenegotiationInfoExtension(self.buffer[offset:ext_boundary]))
			elif TLS_EC_POINTS_FORMATS_EXTENSION_TYPE == ((self.buffer[offset + TLS_EXTENSION_TYPE_OFFSET] << 8) | self.buffer[offset + TLS_EXTENSION_TYPE_OFFSET + 1]):
				extensions.append(TLSECPointsFormatExtension(self.buffer[offset:ext_boundary]))
			elif TLS_HEARTBEAT_EXTENSION_TYPE == ((self.buffer[offset + TLS_EXTENSION_TYPE_OFFSET] << 8) | self.buffer[offset + TLS_EXTENSION_TYPE_OFFSET + 1]):
				extensions.append(TLSHeartbeatExtension(self.buffer[offset:ext_boundary]))
			offset += (ext_length + 
				HANDSHAKE_SERVER_HELLO_EXTENSION_LENGTH_LENGTH + 
				HANDSHAKE_SERVER_HELLO_EXTENSION_TYPE_LENGTH);
			if offset >= length:
				break;
		return extensions
	def add_extension(self, extension):
		pass

TLS_CERTIFICATES_HANDSHAKE_CERTIFICATES_LENGTH_OFFSET = 0x4;
TLS_CERTIFICATES_HANDSHAKE_CERTIFICATES_LENGTH_LENGTH = 0x3;
TLS_CERTIFICATES_HANDSHAKE_CERTIFICATES_OFFSET = 0x7;
TLS_CERTIFICATES_HANDSHAKE_CERTIFICATE_LENGTH_LENGTH = 0x3;
TLS_HANDSHAKE_CERTIFICATE_LENGHT_LENGTH = 0x3;
TLS_HANDSHAKE_TYPE_OFFSET = 0x0;
TLS_HANDSHAKE_LENGTH_OFFSET = 0x1;
TLS_CERTIFICATE_HANDSHAKE_TYPE = 0x0b;
TLS_CERTIFICATES_LENGTH_OFFSET = 0x4;
TLS_CERTIFICATE_LENGTH_LENGTH = 0x3;

class TLSCertificateProtocol(TLSHandshakeProtocol):
	def __init__(self, buffer=None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = ([0] * (
					HANDSHAKE_TYPE_LENGTH +
					HANDSHAKE_LENGTH_LENGTH +
					TLS_HANDSHAKE_CERTIFICATE_LENGHT_LENGTH
				))
			# length = TLS_HANDSHAKE_CERTIFICATE_LENGHT_LENGTH;
			length = (len(self.buffer) - HANDSHAKE_TYPE_LENGTH - HANDSHAKE_LENGTH_LENGTH);
			self.buffer[TLS_HANDSHAKE_TYPE_OFFSET] = TLS_CERTIFICATE_HANDSHAKE_TYPE;
			self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET] = (length >> 16) & 0xFF;
			self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 1] = (length >> 8) & 0xFF;
			self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 2] = (length) & 0xFF;
			self.buffer[TLS_CERTIFICATES_LENGTH_OFFSET] = 0x0;
			self.buffer[TLS_CERTIFICATES_LENGTH_OFFSET + 1] = 0x0;
			self.buffer[TLS_CERTIFICATES_LENGTH_OFFSET + 2] = 0x0;
	def get_certificates_length(self):
		return (
			(self.buffer[TLS_CERTIFICATES_HANDSHAKE_CERTIFICATES_LENGTH_OFFSET] << 16) | 
			(self.buffer[TLS_CERTIFICATES_HANDSHAKE_CERTIFICATES_LENGTH_OFFSET + 1] << 8) |
			self.buffer[TLS_CERTIFICATES_HANDSHAKE_CERTIFICATES_LENGTH_OFFSET + 2]);
	def get_certificates(self):
		offset = TLS_CERTIFICATES_HANDSHAKE_CERTIFICATES_OFFSET;
		has_more_certificates = (self.get_certificates_length() > 0);
		certificates = [];
		while has_more_certificates:
			certificate_length = (
				(self.buffer[offset] << 16) | 
				(self.buffer[offset + 1] << 8) | 
				(self.buffer[offset + 2]));
			certificate = X509v3Certificate(bytes(self.buffer[offset + TLS_CERTIFICATES_HANDSHAKE_CERTIFICATE_LENGTH_LENGTH:
					offset + TLS_CERTIFICATES_HANDSHAKE_CERTIFICATE_LENGTH_LENGTH + certificate_length]));
			certificates.append(certificate);
			offset += TLS_CERTIFICATES_HANDSHAKE_CERTIFICATE_LENGTH_LENGTH + certificate_length;
			if offset == len(self.buffer):
				has_more_certificates = False;
		return certificates;
	def add_certificate(self, certificate):
		offset = len(self.buffer);
		certificate_bytes = certificate.get_bytes();
		certificates_length = ((self.buffer[TLS_CERTIFICATES_LENGTH_OFFSET] << 16) & 0xFF | 
							(self.buffer[TLS_CERTIFICATES_LENGTH_OFFSET + 1] << 8) & 0xFF |
							(self.buffer[TLS_CERTIFICATES_LENGTH_OFFSET + 2]) & 0xFF);
		certificates_length += len(certificate_bytes) + TLS_CERTIFICATE_LENGTH_LENGTH;
		self.buffer[TLS_CERTIFICATES_LENGTH_OFFSET] = ((certificates_length >> 16) & 0xFF);
		self.buffer[TLS_CERTIFICATES_LENGTH_OFFSET + 1] = ((certificates_length >> 8) & 0xFF);
		self.buffer[TLS_CERTIFICATES_LENGTH_OFFSET + 2] = (certificates_length & 0xFF);
		handshake_length = self.get_length();
		handshake_length += len(certificate_bytes) + TLS_CERTIFICATE_LENGTH_LENGTH;
		self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET] = ((handshake_length >> 16) & 0xFF);
		self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 1] = (handshake_length >> 8) & 0xFF;
		self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 2] = (handshake_length & 0xFF);
		self.buffer[offset:offset + TLS_CERTIFICATE_LENGTH_LENGTH] =  [
			((len(certificate_bytes) >> 16) & 0xFF), 
			((len(certificate_bytes) >> 8) & 0xFF), 
			(len(certificate_bytes) & 0xFF)];
		self.buffer[offset + TLS_CERTIFICATE_LENGTH_LENGTH:offset + TLS_CERTIFICATE_LENGTH_LENGTH + len(certificate_bytes)] = certificate_bytes;
class TLSCertificate():
	"""
	TLS certificate
	"""
	def __init__(self, buffer):
		"""
		Initializes the X509 certificate
		"""
		self.certificate = X509v3Certificate(self.buffer)
	def get_signed_certificate(self):
		"""
		Returns X509v3 signed certificate
		"""
		return self.certifcate;
	def is_self_signed(self):
		"""
		Checks whether the certificate is self-signed or not
		"""
		return False
class ECDHSeverParams():
	"""
	Eliptic curve Diffie-Hellman parameters
	"""
	def __init__(self, buffer):
		"""
		Initializes the structure
		"""
		self.buffer = buffer;
	def get_curve_type(self):
		return None;
	def get_named_curve(self):
		return None;
	def get_public_key_length(self):
		return None;
	def get_public_key(self):
		return None;
	def get_signature_length(self):
		return None;
	def get_signature(self):
		return None;
class TLSSeverKeyExchangeProtocol(TLSHandshakeProtocol):
	def __init__(self, buffer):
		self.buffer = buffer;
	def get_key_exchange_params(self):
		return None;

TLS_SERVER_HELLO_HANDSHAKE_TYPE = 0x0e;

class TLSSeverHelloDoneProtocol(TLSHandshakeProtocol):
	def __init__(self, buffer = None):
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = ([0] * (
					HANDSHAKE_TYPE_LENGTH +
					HANDSHAKE_LENGTH_LENGTH
				))
			self.buffer[TLS_HANDSHAKE_TYPE_OFFSET] = TLS_SERVER_HELLO_HANDSHAKE_TYPE;
			self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET] = 0x00;
			self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 1] = 0x00;
			self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 2] = 0x00;
	def set_length(self):
		return;
	def get_length(self):
		return ((self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET] << 16) | 
				(self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 1] << 8) | 
				(self.buffer[TLS_HANDSHAKE_LENGTH_OFFSET + 2]));
	def get_type(self):
		return (self.buffer[TLS_HANDSHAKE_TYPE_OFFSET]);
class TLSCertificateVerifyProtocol(TLSHandshakeProtocol):
	def __init__(self, buffer):
		self.buffer = buffer;
	def get_signature_length(self):
		return None;
	def get_signature(self):
		return None;
class KeyExchangeParams():
	def __init__(self, buffer):
		self.buffer = buffer;
	def get_bytes(self):
		return None;
class ECDHKeyExchangeParams(KeyExchangeParams):
	def __init__(self, buffer):
		self.buffer = buffer;
	def get_curve_type(self):
		return None;
	def get_named_curve(self):
		return None;
	def get_public_key_length(self):
		return None;
	def get_public_key(self):
		return None;
	def get_signature_length(self):
		return None;
	def get_signature(self):
		return None;
class TLSExtension():
	def __init__(self, buffer):
		self.buffer = buffer;
	def get_type(self):
		return ((self.buffer[TLS_EXTENSION_TYPE_OFFSET] << 8) | self.buffer[TLS_EXTENSION_TYPE_OFFSET + 1])
	def get_length(self):
		return ((self.buffer[TLS_EXTENSION_LENGTH_OFFSET] << 8) | self.buffer[TLS_EXTENSION_LENGTH_OFFSET + 1])
class TLSECPointsFormatExtension(TLSExtension):
	def __init_(self, buffer):
		self.buffer = buffer;
class TLSECSupportedGroupsExtension(TLSExtension):
	def __init_(self, buffer):
		self.buffer = buffer;
class TLSHeartbeatExtension(TLSExtension):
	def __init_(self, buffer):
		self.buffer = buffer;
class TLSRenegotiationInfoExtension(TLSExtension):
	def __init_(self, buffer):
		self.buffer = buffer;

TLS_HANDSHAKE_TYPE_FIELD_LENGTH = 0x1;
TLS_HANDSHAKE_LENGTH_FIELD_LENGTH = 0x3;
TLS_HANDSHAKE_VERSION_FIELD_LENGTH = 0x3;
TLS_RECORD_LAYER_MESSAGE_OFFSET = 0x5;
TLS_RECORD_LAYER_TYPE_OFFSET = 0x0;
TLS_RECORD_LAYER_VERSION_OFFSET = 0x1;
TLS_RECORD_LAYER_LENGTH_OFFSET = 0x3;

class TLSRecordLayer():
	"""
	TLS record structure
	"""
	def __init__(self, buffer = None):
		"""
		Initializes the TLS record layer. If the buffer is 
		None, then a defaul packet will be created (it will
		contain zero protocols)
		"""
		self.buffer = buffer;
		if not self.buffer:
			self.buffer = (
					[0] * (TLS_RECORD_LAYER_HEADER_LENGTH)
				);
			self.buffer[TLS_RECORD_LAYER_TYPE_OFFSET] = TLS_CONTENT_TYPE_HANDSHAKE;
			self.buffer[TLS_RECORD_LAYER_VERSION_OFFSET] = (TLS_PROTOCOL_VERSION >> 8) & 0xFF;
			self.buffer[TLS_RECORD_LAYER_VERSION_OFFSET + 1] = (TLS_PROTOCOL_VERSION) & 0xFF;
			self.buffer[TLS_RECORD_LAYER_LENGTH_OFFSET] = 0x0;
			self.buffer[TLS_RECORD_LAYER_LENGTH_OFFSET + 1] = 0x0;
	def get_content_type(self):
		"""
		Gets the content type of the packet
		"""
		return self.buffer[TLS_CONTENT_TYPE_OFFSET];
	def set_content_type(self, content_type):
		"""
		Sets the content type of the packet
		"""
		self.buffer[TLS_CONTENT_TYPE_OFFSET] = content_type;
	def get_version(self):
		"""
		Gets the version of TLS
		"""
		return ((self.buffer[TLS_VERSION_OFFSET] << 8) | self.buffer[TLS_VERSION_OFFSET + 1]);
	def set_version(self, version):
		"""
		Sets the version of the packet
		"""
		self.buffer[TLS_VERSION_OFFSET] = (version >> 8) & 0xFF;
		self.buffer[TLS_VERSION_OFFSET + 1]; (version & 0xFF);
	def get_length(self):
		"""
		Gets the length of the TLS record layer 
		"""
		return ((self.buffer[TLS_LENGTH_OFFSET] << 8) | self.buffer[TLS_LENGTH_OFFSET + 1]);
	def set_length(self, length):
		self.buffer[TLS_LENGTH_OFFSET] = ((length >> 8) & 0xFF);
		self.buffer[TLS_LENGTH_OFFSET + 1] = (length & 0xFF);
	def get_handshake_protocols(self, tls_state):
		"""
		Returns all handshake protocols for the given TLS record
		"""
		if self.get_content_type() != TLS_CONTENT_TYPE_HANDSHAKE:
			return [];
		record_layer_length = self.get_length();
		offset = TLS_RECORD_LAYER_HEADER_LENGTH;
		protocols = [];
		has_more_protocols = True;
		if offset + TLS_PROTOCOL_LENGTH_OFFSET >= len(self.buffer):
			return [];
		while has_more_protocols:
			"""
			Iterates over all protocols and pushes them to the array
			"""
			protocol_length = (((self.buffer[offset + TLS_PROTOCOL_LENGTH_OFFSET] << 16) | 
					(self.buffer[offset + TLS_PROTOCOL_LENGTH_OFFSET + 1] << 8) | 
					(self.buffer[offset + TLS_PROTOCOL_LENGTH_OFFSET + 2])) +
			 		TLS_HANDSHAKE_TYPE_FIELD_LENGTH + 
			 		TLS_HANDSHAKE_LENGTH_FIELD_LENGTH);
			protocol_type = self.buffer[TLS_PROTOCOL_HANDSHAKE_TYPE_OFFSET + offset];
			#print(protocol_type);
			if protocol_type == HANDSHAKE_TYPE_CLIENT_HELLO:
				protocols.append(TLSClientHelloProtocol(self.buffer[offset:offset + protocol_length]));
			elif protocol_type == HANDSHAKE_TYPE_SERVER_HELLO:
				protocols.append(TLSServerHelloProtocol(self.buffer[offset:offset + protocol_length]));
			elif protocol_type == HANDSHAKE_TYPE_CERTIFICATE:
				protocols.append(TLSCertificateProtocol(self.buffer[offset:offset + protocol_length]));
			elif protocol_type == HANDSHAKE_TYPE_CERTIFICATE_VERIFY:
				pass
			elif protocol_type == HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE:
				protocols.append(TLSClientKeyExchangeProtocol(self.buffer[offset:offset + protocol_length]));
			elif protocol_type == HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
				protocols.append(TLSServerKeyExchangeProtocol(self.buffer[offset:offset + protocol_length]));
			elif protocol_type == HANDSHAKE_TYPE_CHANGE_CIPHER_SPEC:
				protocols.append(TLSChangeCipherSpecProtocol(self.buffer[offset:offset + protocol_length]));
			elif protocol_type == HANDSHAKE_TYPE_ENCRYPTED_MESSAGE:
				protocols.append(TLSEncryptedMessageProtocol(self.buffer[offset:offset + protocol_length]));
			elif protocol_type == HANDSHAKE_TYPE_SERVER_HELLO_DONE:
				protocols.append(TLSSeverHelloDoneProtocol(self.buffer[offset:offset + protocol_length]));
			offset += protocol_length;
			if offset - TLS_RECORD_LAYER_HEADER_LENGTH == record_layer_length:
				has_more_protocols = False;
		return protocols;
	def add_handshake_protocol(self, protocol):
		"""
		Adds handshake protocol to the packet. The protocol
		must be an instance of TLSHandshakeProtocol class
		"""
		length = self.get_length();
		length += len(protocol.get_bytes());
		self.set_length(length);
		offset = len(self.buffer);
		self.buffer[offset:offset + len(protocol.get_bytes())] = protocol.get_bytes();
	def add_encrypted_protocol(self, encrypted):
		"""
		Adds encrypted protocol
		"""
		length = self.get_length();
		length += len(encrypted);
		self.set_length(length);
		offset = len(self.buffer);
		self.buffer[offset:offset + len(encrypted)] = encrypted;
	def get_message(self):
		"""
		If no handshake protocols is found in the packet we can look up for the 
		embedded messages.
		"""
		if self.get_content_type() == TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC:
			offset = TLS_RECORD_LAYER_HEADER_LENGTH;
			record_layer_length = self.get_length();
			return self.buffer[offset:offset + record_layer_length];
		return None;
	def set_message(self, message):
		"""
		Sets the message
		"""
		length = len(message);
		self.set_length(length);
		self.buffer[TLS_RECORD_LAYER_MESSAGE_OFFSET:TLS_RECORD_LAYER_MESSAGE_OFFSET + length] = message;
	def get_bytes(self):
		"""
		Returns raw packet bytes. This is handy for example
		when sending the packet using socket.
		"""
		return self.buffer;
	def get_bytes_without_header(self):
		"""
		Returns record layer payload without header information
		"""
		offset = TLS_RECORD_LAYER_MESSAGE_OFFSET;
		length = self.get_length();
		return self.buffer[offset:offset + length];