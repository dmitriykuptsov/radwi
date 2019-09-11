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

from Crypto.Cipher import AES

class SymmetricCrypto():
	def encrypt(key, data):
		pass
	def decrypt(key, data):
		pass

# 256 bit key
KEY_SIZE = AES.block_size * 2
BLOCK_SIZE = AES.block_size
IV_SIZE = BLOCK_SIZE

# PKCS7 padding is described in
# https://tools.ietf.org/html/rfc5652
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


AES_CBC_MODE = AES.MODE_CBC;

class AESCipher():
	def __init__(self, mode, key, iv):
		"""
		Initializes the AES cipher. If mode is not CBC then
		exception will be raised. Also, if key length is not 256
		bits, then exception will be raised.
		We should, however, support AES 128 because TLS 
		must support it
		"""
		if mode != AES_CBC_MODE:
			raise Exception("Invalid decryption mode");
		if len(key) != KEY_SIZE:
			raise Exception("Invalid key size");
		if len(iv) != IV_SIZE:
			raise Exception("Invalid initialization vector");
		self.mode = AES.MODE_CBC;
		self.key = key;
		self.iv = iv;

	def encrypt(self, plaintext):
		"""
		Encryptes the plaintext using AES 256 cipher in CBC mode.
		"""
		cipher = AES.new(self.key, self.mode, self.iv);
		return cipher.encrypt(plaintext);

	def decrypt(self, ciphertext):
		"""
		This method decryptes the ciphertext using AES 256 cipher in CBC mode
		"""
		cipher = AES.new(self.key, self.mode, self.iv);
		return cipher.decrypt(ciphertext);