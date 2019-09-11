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

from flask import jsonify
from tokens import Token
import binascii
import os
import random
import string

class Utils():
	DEFAULT_ENTROPY = 128
	@staticmethod
	def make_response(data, status_code):
		"""
		Makes the response for the given data and HTTP response code
		"""
		response = jsonify(data);
		response.status_code = status_code;
		return response

	@staticmethod
	def get_token(cookie):
		"""
		Extracts the security token from the cookie
		"""
		token = Token.decode(cookie);
		if Token.is_valid(token):
			return token;
		return None

	@staticmethod
	def token_hex(nbytes=None):
		"""
		Generates random number of length n bytes and encodes the result using base 16 encoding 
		"""
		if nbytes is None:
			nbytes = Utils.DEFAULT_ENTROPY
		random_bytes = os.urandom(nbytes)
		return binascii.hexlify(random_bytes).decode('ascii')

	@staticmethod
	def random_string(length=10):
		"""Generate a random string of fixed length """
		symbols = string.ascii_lowercase + string.ascii_uppercase + string.digits;
		return ''.join(random.choice(symbols) for i in range(0, length))
	