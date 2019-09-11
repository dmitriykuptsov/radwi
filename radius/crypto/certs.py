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
Cryptographic libraries
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.asn1 import *
from crypto.digest import SHA256Digest
from crypto.rsa import RSACrypto

"""
Base 64 encoding decoding routines
"""
from base64 import b64decode
from base64 import b64encode
"""
Base 16 encoding and decoding routines
"""
import binascii

"""
System library
"""
import sys

"""
Helper methods
"""
from utils import Utils


"""
X509 certificate version
"""
X509_VERSION = 0x2;

"""
DER string types
"""
UTF_STRING = 0x0c;
ASCII_STRING = 0x17;
PRINTABLE_STRING = 0x13;

class DerUTF8String(DerObject):
	"""
	DER encoding UTF8 string object
	"""
	def __init__(self):
		pass
	
	def decode(self, bytes):
		"""
		Decode the UTF8 string
		"""
		if bytes[0] == 0x0c:
			length = bytes[1];
			return bytes[2:length + 2].decode("UTF-8");
		else:
			raise Exception("Not an UTF8 string");
	def encode(self, string):
		"""
		Encodes the string using DER format
		"""
		bytes = [0x0c, len(string)];
		bytes[2:len(string)] = map(ord, a);

class DerAsciiString(DerObject):
	"""
	DER encoding ASCII string object
	"""
	def __init__(self):
		pass
	def decode(self, bytes):
		"""
		Decodes the ASCII string
		"""
		if bytes[0] == 0x17 or bytes[0] == 0x13:
			length = bytes[1];
			return bytes[2:length + 2];
		else:
			raise Exception("Not an ASCII string");
	def encode(self, string):
		"""
		Encodes ASCII string using DER format
		"""
		bytes = [0x17, len(string)];
		bytes[2:len(string)] = map(ord, a);

class PublicKeyInfo():
	"""
	Public key info. A wrapper class for public key
	"""
	def __init__(self, buffer):
		self.buffer = buffer;
	def get_algorithm(self):
		return None;
	def get_modulus(self):
		return None;
	def get_public_exponent(self):
		return None;

class RelativeDistinguishedName():
	"""
	Relative distringuished name
	"""
	def __init__(self, type, value):
		self.type = type;
		self.value = value;
	def get_type(self):
		return self.type;
	def get_value(self):
		return self.value;

class X509v3Extension():
	"""
	X509 certificate extension
	"""
	def __init__(self, buffer):
		pass;
	def get_extension_id(self):
		return None

class X509v3BasicConstraintsExtension(X509v3Extension):
	def __init__(self, buffer):
		pass
	def get_basic_constraints_syntax(self):
		return None;

class X509v3SubjectKeyIdentifierExtension(X509v3Extension):
	def __init__(self, buffer):
		pass
	def get_subject_key_identifier(self):
		return None;

class X509v3AuthorityKeyIdentifierExtension(X509v3Extension):
	def __init__(self, buffer):
		pass
	def get_authority_key_identifier(self):
		return None;
	def get_authority_cert_issuer(self):
		return None;
	def get_authority_cert_serial_number(self):
		return None;

class X509v3CommentExtension(X509v3Extension):
	def __init__(self, buffer):
		pass
	def get_comment(self):
		return None;

class X509v3AltNameExtension(X509v3Extension):
	def __init__(self, buffer):
		pass
	def get_alt_name(self):
		return None;

class X509v3IssuerAltNameExtension(X509v3Extension):
	def __init__(self, buffer):
		pass
	def get_issuer_alt_name(self):
		return None;

# https://tools.ietf.org/html/rfc5280#section-4.1
class X509v3Certificate():
	@staticmethod
	def generate_self_signed_certificate():
		return None
	@staticmethod
	def load(filename):
		"""
		Loads the certificate from PEM file and then parses it
		"""
		buffer = [];
		b64_contents = "";
		try:
			handle = open(filename, "r");
			raw_contents = handle.readlines();
			for line in raw_contents:
				if line.startswith("----"):
					continue
				b64_contents += line.strip();
		except Exception as e:
			raise Exception("Failed to read PEM file: " + str(e));
		buffer = b64decode(b64_contents);
		return X509v3Certificate(buffer);
	 
	def __init__(self, buffer):
		"""
		Initializes the buffer and parses certificate according to ASN.1 notation
		"""
		self.buffer = buffer;
		certificate = DerSequence();
		certificate.decode(self.buffer);
		tbsCertificate = DerSequence();
		tbsCertificate.decode(certificate[0]);
		self.certificate_bytes = bytearray(certificate[0]);
		algorithm_identifier = DerSequence();
		algorithm_identifier.decode(certificate[1]);
		signature_algorithm = DerObjectId();
		signature_algorithm.decode(algorithm_identifier[0]);
		signature_algorithm_in_cert = signature_algorithm.value;
		signature = DerBitString();
		self.signature_value = signature.decode(certificate[2]).value;
		version = DerObject();
		version.decode(tbsCertificate[0]);
		version_num = DerInteger();
		# Must be sha256WithRSA
		self.version = version_num.decode(version.payload);
		self.serial_number = tbsCertificate[1];
		algorithm_identifier = DerSequence();
		algorithm_identifier.decode(tbsCertificate[2]);
		signature_algorithm = DerObjectId();
		signature_algorithm.decode(algorithm_identifier[0]);
		self.signature_algorithm = signature_algorithm.value;
		if self.signature_algorithm != "1.2.840.113549.1.1.11":
			raise Exception("Unsupported algorithm. MUST be sha256WithRSA")
		if signature_algorithm_in_cert != self.signature_algorithm:
			raise Exception("Algorithm mismatch");
		issuer_name_seq = DerSequence();
		issuer_name_seq.decode(tbsCertificate[3]);
		self.issuer = [];
		for i in range(0, len(issuer_name_seq)):
			rdnSet = DerSetOf();
			rdnSet.decode(issuer_name_seq[i]);
			for j in range(0, len(rdnSet)):
				rdnAttrs = DerSequence();
				rdnAttrs.decode(rdnSet[j]);
				attr_type = DerObjectId();
				if rdnAttrs[1][0] == UTF_STRING:
					self.issuer.append(
						RelativeDistinguishedName(
							attr_type.decode(rdnAttrs[0]).value, DerUTF8String().decode(rdnAttrs[1])));
				elif rdnAttrs[1][0] == ASCII_STRING or rdnAttrs[1][0] == PRINTABLE_STRING:
					self.issuer.append(
						RelativeDistinguishedName(
							attr_type.decode(rdnAttrs[0]).value, DerAsciiString().decode(rdnAttrs[1])));
		validity_seq = DerSequence();
		validity = validity_seq.decode(tbsCertificate[4]);
		self.validity_not_before = DerAsciiString().decode(validity[0]);
		self.validity_not_after = DerAsciiString().decode(validity[1]);
		subject_name_seq = DerSequence();
		subject_name_seq.decode(tbsCertificate[5]);
		self.subject = [];
		for i in range(0, len(subject_name_seq)):
			rdnSet = DerSetOf();
			rdnSet.decode(subject_name_seq[i]);
			for j in range(0, len(rdnSet)):
				rdnAttrs = DerSequence();
				rdnAttrs.decode(rdnSet[j]);
				attr_type = DerObjectId();
				if rdnAttrs[1][0] == UTF_STRING:
					self.subject.append(
						RelativeDistinguishedName(
							attr_type.decode(rdnAttrs[0]).value, DerUTF8String().decode(rdnAttrs[1])));
				elif rdnAttrs[1][0] == ASCII_STRING or rdnAttrs[1][0] == PRINTABLE_STRING:
					self.subject.append(
						RelativeDistinguishedName(
							attr_type.decode(rdnAttrs[0]).value, DerAsciiString().decode(rdnAttrs[1])));
		subjectPublicKeyInfo = tbsCertificate[6];
		# Initialize RSA key
		self.rsa_key = RSA.importKey(subjectPublicKeyInfo);
		"""
		Still need to add decoding of extensions
		"""

	def get_bytes(self):
		"""
		Gets DER encoded certificate
		"""
		return self.buffer;
	def get_version(self):
		"""
		Returns the version of the X509 certificate
		"""
		return self.version;
	def get_serial_number(self):
		"""
		Gets certificate certial number
		"""
		return self.serial_number;
	def get_signature_algorithm(self):
		"""
		Gets the signature algorithm
		"""
		return self.signature_algorithm;
	def get_issuer(self):
		"""
		Gets the issuer of the certificate as RDNs as list of RDNs
		"""
		return self.issuer;
	def get_validity_not_before(self):
		"""
		Returns string representing 
		the start time of the certificate
		"""
		return self.validity_not_before;
	def get_validity_not_after(self):
		"""
		Returns string representing 
		the end time of the certificate
		"""
		return self.validity_not_after;
	def get_subject(self):
		"""
		Returns the subject of the certificate
		as a list of RDNs
		"""
		return self.subject;
	def get_public_key_info(self):
		"""
		Returns the certifcate public key 
		"""
		return self.rsa_key;
	def get_extensions(self):
		"""
		Gets the extensions of the certificate
		"""
		return None;
	def get_algorithm_identifier(self):
		"""
		Gets certificate algorithm identifier
		"""
		return self.signature_algorithm;
	def get_signature(self):
		"""
		Gets the signature (SHA256WithRSA) value
		"""
		return self.signature_value;
	def get_certificate(self):
		"""
		Returns unsigned certficate bytes
		"""
		return self.certificate_bytes;
	def verify(self, public_key):
		"""
		Verifies the certificate:
			- First SHA256 digest is computed and is padded
			- Second computed signature is decrypted using public key
			- The bytes in the padded SHA256 signature are compared to bytes in decrypted message
			- If both are equal, the signature verification process succeeded
		"""
		return RSACrypto().verify(self.certificate_bytes, self.get_signature(), public_key);

# https://tools.ietf.org/html/rfc3447#appendix-A
class RSAPublicKey():
	@staticmethod
	def load(filename):
		"""
		Loads the RSA private key from PEM file and then parses the key
		"""
		buffer = [];
		b64_contents = "";
		try:
			handle = open(filename, "r");
			raw_contents = handle.readlines();
			for line in raw_contents:
				if line.startswith("----"):
					continue
				b64_contents += line.strip();
		except Exception as e:
			raise Exception("Failed to read PEM file: " + str(e));
		buffer = b64decode(b64_contents);
		return RSAPrivateKey(buffer);

	def __init__(self, buffer):
		"""
		Initializes the buffer
		"""
		self.key = RSA.importKey(buffer)
	def get_key_info(self):
		"""
		Returns the RSA public key
		"""
		return self.key;
	def get_modulus(self):
		"""
		Gets the modulus 
		"""
		return self.key.n;
	def get_public_exponent(self):
		"""
		Gets the public exponent of the key
		"""
		return self.key.d;

class RSAPrivateKey():
	@staticmethod
	def load(filename):
		"""
		Loads the RSA private key from PEM file and then parses the key
		"""
		buffer = [];
		b64_contents = "";
		try:
			handle = open(filename, "r");
			raw_contents = handle.readlines();
			for line in raw_contents:
				if line.startswith("----"):
					continue
				b64_contents += line.strip();
		except Exception as e:
			raise Exception("Failed to read PEM file: " + str(e));
		buffer = b64decode(b64_contents);
		return RSAPrivateKey(buffer);
	def __init__(self, buffer):
		self.key=RSA.importKey(buffer)
	def get_key_info(self):
		"""
		Returns the RSA private key
		"""
		return self.key;
	def get_modulus(self):
		"""
		Gets the modulus 
		"""
		return self.key.n;
	def get_p_prime(self):
		"""
		Gets the first prime of the key.
		"""
		return self.key.p;
	def get_q_prime(self):
		"""
		Gets the second prime of the key
		"""
		return self.key.q;
	def get_private_exponent(self):
		"""
		Gets the private exponent
		"""
		return self.key.d;
