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

import MySQLdb
import re

MYSQL_DRIVER = "mysql";
CASSANDRA_DRIVER = "cassandra";

class Database():
	def __init__(self, config):
		"""
		Initializes the driver
		"""
		if config["database"]["driver"] == MYSQL_DRIVER:
			self.db = MySQLdb.connect(host=config["database"]["host"],
				user=config["database"]["user"],
				passwd=config["database"]["password"],
				db=config["database"]["database"],
				charset="utf8");
			self.cursor = self.db.cursor(MySQLdb.cursors.DictCursor);
		elif config["database"]["driver"] == CASSANDRA_DRIVER:
			raise Exception("Not implemented");
		else:
			raise Exception("Unsupported DB driver");
		self.salt = config["database"]["salt"];
	def disconnect(self):
		"""
		Disconnects from the database
		"""
		self.db.close();
	def authenticate(self, username, password):
		"""
		Authenticates the user
		"""
		if not re.match("[a-zA-Z0-9]{5,20}", username):
			return False;
		if not re.match("[a-zA-Z0-9]{5,20}", password):
			return False;
		query = """
			SELECT u.id AS user_id, u.username FROM rad_users u 
			INNER JOIN balance b ON u.id = b.user_id 
			INNER JOIN tariff t ON b.tariff_id = t.id 
			WHERE u.username = %s AND u.password = SHA2(CONCAT(%s, %s), 256) AND 
			b.balance / t.price_per_megabyte > 0 AND u.blocked <> TRUE
		""";
		self.cursor.execute(query, (username, self.salt, password));
		result = self.cursor.fetchall();
		if len(result) != 0x1:
			return False;
		if result[0]["username"] != username:
			return False;
		return True;
	def get_bytes_remaining_and_conn_speed(self, username):
		"""
		Estimates how many bytes the user can send or receive in total
		"""
		if not re.match("[a-zA-Z0-9]{5,20}", username):
			return False;
		query = """SELECT b.balance / t.price_per_megabyte * 1024 * 1024 AS bytes_remaining, t.conn_speed_in_kbytes_per_second FROM rad_users u 
					INNER JOIN balance b ON u.id = b.user_id 
					INNER JOIN tariff t ON b.tariff_id = t.id 
					WHERE u.username = %s  AND u.blocked <> TRUE
				""";
		self.cursor.execute(query, (username,));
		result = self.cursor.fetchall();
		if len(result) != 0x1:
			return 0;
		return (result[0]["bytes_remaining"], result[0]["conn_speed_in_kbytes_per_second"]);
