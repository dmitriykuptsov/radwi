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

from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

class AsymmetricCrypto():
	"""
	Base class for asymmetric cryptography
	"""
	def __init__(self):
		return None
	def generate_key_pair(self, params):
		"""
		Generates new key pair
		"""
		raise Exception("Method was not implemented");
	def encrypt(self, data, key):
		"""
		Encrypts plaintext information using private key
		"""
		raise Exception("Method was not implemented");
	def decrypt(self, data, key):
		"""
		Decrypts ciphertext using private key
		"""
		raise Exception("Method was not implemented");
	def verify(self, data, signature, key):
		"""
		Verifies the signature 
		"""
		raise Exception("Method was not implemented");

class RSACrypto(AsymmetricCrypto):
	def __init__(self):
		"""
		Initializes the RSA crypto engine
		"""
		return None
	def generate_key_pair(self, params):
		"""
		Generates RSA key pair
		"""
		return None
	def encrypt(self, data, key):
		"""
		Encrypts a message using public key

		The RSAES-OAEP encryption scheme defined in [PKCS1] is more secure
		against the Bleichenbacher attack.  However, for maximal
		compatibility with earlier versions of TLS, this specification uses
		the RSAES-PKCS1-v1_5 scheme.  No variants of the Bleichenbacher
		attack are known to exist provided that the above recommendations are
		followed.
		"""
		cipher = PKCS1_v1_5.new(key);
		return cipher.encrypt(data);
	def decrypt(self, data, key):
		"""
		Decrypts the data using private key

		The RSAES-OAEP encryption scheme defined in [PKCS1] is more secure
		against the Bleichenbacher attack.  However, for maximal
		compatibility with earlier versions of TLS, this specification uses
		the RSAES-PKCS1-v1_5 scheme.  No variants of the Bleichenbacher
		attack are known to exist provided that the above recommendations are
		followed.
		"""
		cipher = PKCS1_v1_5.new(key);
		return cipher.decrypt(data, None);
	def verify(self, data, signature, key):
		"""
		PKCS1 v1.5 signature verification


		"""
		try:
			"""
			If signature verification fails an exception will be raised,
			otherwise the method will complete its execution without any
			errors meaning that the signature verification procedure 
			suceeded.
			"""
			digest = SHA256.new(data);
			pkcs1_15.new(key).verify(digest, signature);
			return True
		except (ValueError, TypeError):
			return False

	def sign(self, data, key):
		"""
		PKCS1 v1.5 signature
		"""
		digest = SHA256.new(data);
		return pkcs1_15.new(key).sign(digest);

