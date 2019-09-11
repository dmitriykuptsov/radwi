# -*- coding: utf-8 -*-
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

import json
import time
from config import config
from scrypto import AESCipher

cipher = AESCipher(config["MASTER_SECRET"]);
nonce = config["SERVER_NONCE"];

class Token:
	"""
	Secure token which is used for authentication and authorization purposes
	"""
	@staticmethod
	def is_valid(token):
		"""
		Verifies whether the token is valid:
			(i) Checks whether the server nonce which is found in token is the same as in configuration file
			(ii) Checks wether the validity time in token grater than the current system time
		For the correct operation of the token verification the system clock MUST be synced
		"""
		try:
			if not token:
				return False
			if token["server_nonce"] != nonce:
				return False
			now = int(time.mktime(time.gmtime()))
			return now <= token["valid_until"];
		except:
			return False

	@staticmethod
	def get_token_hash(token):
		"""
		Returns the hash value stored in the token. Hash is a random value and adds extra entropy to the token. 
		"""
		if Token.is_valid():
			return token["token"];
		else:
			return None

	@staticmethod
	def get_user_id(token):
		"""
		Returns the user ID which is stored in the token
		"""
		if not token:
			return None
		if Token.is_valid(token):
			return token["user_id"];
		return None

	@staticmethod
	def decode(token):
		"""
		Decodes the token:
			(i) the token is decrypted using AES cipher
			(ii) the result is parsed using JSON parser
		"""
		try:
			token = cipher.decrypt(token);
			return json.loads(token);
		except:
			return None

	@staticmethod
	def encode(user_id, hased_token, server_nonce, expires_in):
		"""
		Encodes the token by encrypting the JSON document using AES cipher
		"""
		now = int(time.mktime(time.gmtime()))
		valid_until = now + expires_in;
		token = json.dumps({
			"token": hased_token,
			"valid_until": valid_until,
			"user_id": user_id,
			"server_nonce": server_nonce
			});
		return cipher.encrypt(token);
