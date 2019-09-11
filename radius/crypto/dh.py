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

class KeyExchange():
	"""
	Base key exchange buffer
	"""
	def generate_key_pair(self, params):
		"""
		Generates new key pair
		"""
		return None
	def derive_secret(self, public_key):
		"""
		Computes secret key
		"""
		return None

class DHKeyExchange(KeyExchange):
	"""
	Diffie-Hellman key exchange class
	"""
	def generate_key_pair(self):
		"""
		Generates new Diffie-Hellman keypair
		"""
		return None
	def derive_secret(self, public_key):
		"""
		Derives new secret
		"""
		return None

class ECDHKeyExchange(KeyExchange):
	"""
	Eliptic-curve Diffie Hellman
	"""
	def generate_key_pair(self):
		"""
		Generates ECDH key pair
		"""
		return None
	def derive_secret(self):
		"""
		Derive shared secret
		"""
		return None
