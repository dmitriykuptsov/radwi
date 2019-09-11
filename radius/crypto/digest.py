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

from Crypto.Hash import SHA256
from Crypto.Hash import MD5
from Crypto.Hash import HMAC

class Digest():
	"""
	Base class
	"""
	def digest(self, data):
		raise Exception("Method was not implemented");

class HMACDigest():
	"""
	Base class
	"""
	def digest(self, secret, data):
		raise Exception("Method was not implemented");	

class MD5Digest(Digest):
	"""
	Old MD5 digest algorithm, which will be needed 
	in RADIUS authentication, encryption and password
	hiding mechanims
	"""
	def digest(self, data):
		"""
		Computes MD5 hash for the given data
		"""
		h = MD5.new()
		h.update(data)
		return h.digest()

class HMACMD5(HMACDigest):
	"""
	Computes MD5-HMAC
	"""
	def digest(self, secret, data):
		"""
		Computes keyed MD5 hash for the given data
		"""
		h = HMAC.new(secret, digestmod=MD5)
		h.update(data)
		return h.digest()

class HMACSHA256(HMACDigest):
	"""
	Computes MD5-HMAC
	"""
	def digest(self, secret, data):
		"""
		Computes keyed MD5 hash for the given data
		"""
		h = HMAC.new(secret, digestmod=SHA256)
		h.update(data)
		return h.digest()
		
class SHA1Digest(Digest):
	"""
	SHA1 digest algorithm
	"""
	def digest(self, data):
		"""
		Computes hash value for the given data
		"""
		return None

class SHA256Digest(Digest):
	"""
	SHA256 digest algorithm
	"""
	def digest(self, data):
		"""
		Computes the SHA256 digest, or hash, for the given data 
		"""
		h = SHA256.new()
		h.update(data)
		return h.digest()

