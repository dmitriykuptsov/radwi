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

from flask import Flask
from flask import request, jsonify
from flask import json,Response,send_file
from flask import g
from logging.config import dictConfig
import decimal
import MySQLdb
import hashlib
import random
import datetime
import os
import re
from flask import Response
from math import sqrt
from math import pow
import sys
import json
from math import log
import base64
import traceback
from config import config
from tokens import Token
from utils import Utils

"""
Create intsance of Flask application
"""
app = Flask(__name__);

"""
Initialize the random number generator with 1024 bit random number obtained from OS source
"""
random.seed(os.urandom(128));

def connect_to_database():
	"""
	Helper method which allows the process to connect to the database
	"""
	return MySQLdb.connect(host=config["DB_HOST"],
		user=config["DB_USER"],
		passwd=config["DB_PASSWORD"],
		db=config["DB"],
		charset="utf8");

@app.before_request
def db_connect():
	"""
	Connects to the database before request
	"""
	g.db = connect_to_database();
	g.cur = g.db.cursor(MySQLdb.cursors.DictCursor);

@app.teardown_request
def db_disconnect(exception=None):
	"""
	Disconnects from the database after response was sent
	"""
	g.db.close();

@app.route("/api/authenticate/", methods=["POST"])
def authenticate():
	"""
	Authenticates the user using username and password found in submitted JSON document
	"""
	try:
		data = json.loads(request.stream.read());
	except:
		return Utils.make_response({
			"status": "failure",
			"reason": "Unable to decode the JSON payload"
		}, 400);
	username = data.get("username") or "";
	password = data.get("password") or "";
	if not re.match("^[a-z0-9]{5,100}$", username):
		return Utils.make_response({
			"status": "failure",
			"reason": "Invalid username"
		}, 403);
	if not re.match("^(?=.*[A-Z]+)(?=.*[a-z]+)(?=.*[0-9]+)", password) or not re.match("^[a-zA-Z0-9]{10,100}$", password):
		return Utils.make_response({
			"status": "failure",
			"reason": "Invalid password"
		}, 403);
	random_token = Utils.token_hex();
	query = "SELECT u.id AS user_id FROM users u WHERE u.username = %s AND u.password = SHA2((%s), 256);";
	g.cur.execute(query, [username, password + config["PASSWORD_SALT"]]);
	row = g.cur.fetchone();
	if not row:
		return Utils.make_response({
			"status": "failure",
			"reason": "Invalid username or password"
		}, 403);
	user_id = row["user_id"];
	expire_date = datetime.datetime.utcnow() + datetime.timedelta(seconds=config["MAX_SESSION_DURATION_IN_SECONDS"])
	response = Utils.make_response({
			"status": "success"
		}, 200);
	"""
	Create encrypted cookie using server master secret
	"""
	response.set_cookie(
			"token", 
			Token.encode(
				user_id, 
				random_token,
				config["SERVER_NONCE"],
				config["MAX_SESSION_DURATION_IN_SECONDS"]), 
			secure=False,
			httponly=True,
			expires=expire_date,
			samesite="Strict");
	return response

@app.route("/api/logout/")
def logout():
	"""
	Removes the cookie from the user's file system
	"""
	response = Utils.make_response({
		"status": "success"
	}, 200);
	response.set_cookie("token", "", expires=0);
	return response

@app.route("/api/check_token/")
def check_token():
	"""
	Checks the token validity. Returns HTTP 200 on success, otherwise HTTP 403 is returned
	"""
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	else:
		return Utils.make_response({
			'status': 'success'
			}, 200);

@app.route("/api/change_password/", methods=["POST"])
def change_password():
	"""
	Changes the password of the user
	"""
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	try:
		data = json.loads(request.stream.read());
	except:
		return Utils.make_response({
			"status": "failure",
			"reason": "Unable to decode the JSON payload"
		}, 400);
	username = data.get("username") or "";
	old_password = data.get("old_password") or "";
	if not re.match("^(?=.*[A-Z]+)(?=.*[a-z]+)(?=.*[0-9]+)", old_password) or not re.match("^[a-zA-Z0-9]{10,100}$", old_password):
		return Utils.make_response({
			"status": "failure",
			"reason": "Invalid old password"
		}, 403);
	new_password = data.get("new_password") or "";
	if not re.match("^(?=.*[A-Z]+)(?=.*[a-z]+)(?=.*[0-9]+)", new_password) or not re.match("^[a-zA-Z0-9]{10,100}$", new_password):
		return Utils.make_response({
			"status": "failure",
			"reason": "Invalid new password"
		}, 403);
	query = "SELECT u.id AS user_id FROM users u WHERE u.username = %s AND u.password = SHA2((%s), 256);";
	g.cur.execute(query, [username, old_password + config["PASSWORD_SALT"]]);
	row = g.cur.fetchone();
	if not row:
		return Utils.make_response({
			"status": "failure",
			"reason": "Invalid old password"
		}, 403);
	user_id = Token.get_user_id(token);
	if user_id != row["user_id"]:
		return Utils.make_response({
			"status": "failure",
			"reason": "Invalid username"
			}, 403);
	query = "UPDATE users SET password = SHA2((%s), 256) WHERE id = %s;";
	g.cur.execute(query, [new_password + config["PASSWORD_SALT"], user_id]);
	g.db.commit();
	random_token = Utils.token_hex();
	expire_date = datetime.datetime.utcnow() + datetime.timedelta(seconds=config["MAX_SESSION_DURATION_IN_SECONDS"])
	response = Utils.make_response({
			"status": "success"
		}, 200);
	response.set_cookie(
			"token", 
			Token.encode(
				user_id, 
				random_token,
				config["SERVER_NONCE"],
				config["MAX_SESSION_DURATION_IN_SECONDS"]), 
			secure=False,
			httponly=True,
			expires=expire_date,
			samesite="Strict");
	return response

@app.route("/api/count_vouchers/")
def count_vouchers():
	"""
	Counts all vouchers in the system
	"""
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	query = "SELECT COUNT(*) AS number_of_vouchers FROM rad_users";
	g.cur.execute(query);
	row = g.cur.fetchone();
	return Utils.make_response({
		"status": "success",
		"number_of_vouchers": row["number_of_vouchers"]
	}, 200);

@app.route("/api/get_vouchers/:offset/:limit/")
def get_vouchers(offset, limit):
	"""
	Returns vouchers from the database using given offset and limit
	"""
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	query = "SELECT u.username, u.blocked, b.balance, t.price_per_megabyte, t.conn_speed_in_kbytes_per_second FROM rad_users u INNER JOIN balance b ON b.user_id = u.id INNER JOIN tariff t ON t.id = b.tariff_id LIMIT ? OFFSET ?";
	g.cur.execute(query, (limit, offset));
	rows = g.cur.fetchall();
	vouchers = [];
	for row in rows:
		vouchers.append({
				"username": row["username"],
				"blocked": row["blocked"],
				"balance": row["balance"],
				"price_per_megabyte": row["price_per_megabyte"],
				"conn_speed_in_kbytes_per_second": row["conn_speed_in_kbytes_per_second"]
			});
	return Utils.make_response({
		"status": "success",
		"vouchers": vouchers
	}, 200);

@app.route("/api/get_voucher/:id/")
def get_voucher(id):
	"""
	Gets the voucher by identifier
	"""
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	query = "SELECT u.username, u.blocked, b.balance, t.price_per_megabyte, t.conn_speed_in_kbytes_per_second FROM rad_users u INNER JOIN balance b ON b.user_id = u.id INNER JOIN tariff t ON t.id = b.tariff_id WHERE u.id = ?";
	g.cur.execute(query, (id));
	row = g.cur.fetchone();
	if not row:
		return Utils.make_response({
			'status': 'failure'
			}, 404);
	voucher = {
			"username": row["username"],
			"blocked": row["blocked"],
			"balance": row["balance"],
			"price_per_megabyte": row["price_per_megabyte"],
			"conn_speed_in_kbytes_per_second": row["conn_speed_in_kbytes_per_second"]
		};
	return Utils.make_response({
		"status": "success",
		"voucher": voucher
	}, 200);

@app.route("/api/generate_voucher/:tariff_id/", methods=["POST"])
def generate_voucher(tariff_id):
	"""
	Generates new voucher
	"""
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	voucher = Utils.random_string(config["VOUCHER_USERNAME_LENGTH"]);
	password = Utils.random_string(config["VOUCHER_PASSWORD_LENGTH"]);
	query = "SELECT * FROM tariff WHERE id = ?";
	g.cur.execute(query, (tariff_id,));
	row = g.cur.fetchone();
	if not row:
		return Utils.make_response({
			'status': 'failure'
			}, 404);

	try:
		query = "LOCK TABLES rad_users WRITE, balance WRITE";
		g.cur.execute(query);
		query = "INSERT INTO rad_users(username, password, blocked) VALUES(?, SHA2(CONCAT(?, ?), 256), TRUE);";
		g.cur.execute(query, (username, config["PASSWORD_SALT"], password));
		query = "SELECT MAX(id) AS user_id FROM rad_users";
		g.cur.execute(query);
		row = g.cur.fetchone();
		user_id = row["user_id"];
		query = "INSERT INTO balance(user_id, balance, tariff_id) VALUES(?, 0, ?);"
		g.cur.execute(query, (user_id, tariff_id));
		query = "UNLOCK TABLES rad_users, balance"
		g.cur.execute(query);
		g.db.commit();
	except:
		g.db.rollback();
	return Utils.make_response({
		"status": "success",
		"voucher": {
			"voucher": voucher,
			"password": password
		}
	}, 200);

@app.route("/api/update_balance/:id/:balance/")
def update_balance(id, balance):
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	query = "UPDATE balance SET balance = ? WHERE user_id = ?";
	g.cur.execute(query, (balance, id));
	row = g.cur.fetchone();
	if not row:
		return Utils.make_response({
			"status": "failure"
		}, 404);
	return Utils.make_response({
		"status": "success",
		"balance": row["balance"]
	}, 200);

@app.route("/api/get_balance/:id/")
def get_balance(id):
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	query = "SELECT balance FROM balance WHERE user_id = ?";
	g.cur.execute(query, (id));
	row = g.cur.fetchone();
	if not row:
		return Utils.make_response({
			"status": "failure"
		}, 404);
	return Utils.make_response({
		"status": "success",
		"balance": row["balance"]
	}, 200);

@app.route("/api/get_tariff/")
def get_tariff():
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	query = "SELECT * FROM tariff";
	g.cur.execute(query);
	row = g.cur.fetchone();
	return Utils.make_response({
		"status": "success",
		"tariff": {
			"id": row["id"],
			"price_per_megabyte": row["price_per_megabyte"],
			"conn_speed_in_bytes_per_second": row["conn_speed_in_bytes_per_second"]
		}
	}, 200);

@app.route("/api/update_tariff/", methods=["POST"])
def update_tariff():
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	try:
		data = json.loads(request.stream.read());
	except:
		return Utils.make_response({
			"status": "failure",
			"reason": "Unable to decode the JSON payload"
		}, 400);
	tariff_id = data["id"];
	price_per_megabyte = data["price_per_megabyte"];
	conn_speed_in_kbytes_per_second = data["conn_speed_in_kbytes_per_second"]
	query = "UPDATE tariff SET price_per_megabyte = ?, conn_speed_in_kbytes_per_second = ? WHERE id = ?";
	g.cur.execute(query, (price_per_megabyte, conn_speed_in_kbytes_per_second, tariff_id));
	g.db.commit();
	return Utils.make_response({
		"status": "success"
	}, 200);

@app.route("/api/get_statistics/:id/")
def get_statistics(id):
	"""
	Returns statistics for specific voucher
	"""
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	query = "SELECT start_time, end_time, session_id, bytes_transmitted FROM rad_acct WHERE user_id = ?";
	g.cur.execute(query, (id));
	rows = g.cur.fetchall();
	accouting_stats = [];
	for row in rows:
		accouting_stats.append({
			"start_time": row["start_time"],
			"end_time": row["end_time"],
			"session_id": row["session_id"],
			"bytes_transmitted": row["bytes_transmitted"]
			});
	return Utils.make_response({
		"status": "success",
		"stats": accouting_stats
	}, 200);

@app.route("/api/block_user/:id/")
def block_user(id):
	"""
	Blocks the user
	"""
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	query = "UPDATE rad_users SET blocked = TRUE WHERE id = ?";
	g.cur.execute(query, (id));
	g.cur.commit();
	return Utils.make_response({
		"status": "success"
	}, 200);

@app.route("/api/unblock_user/:id/")
def unblock_user(id):
	"""
	Unblocks the user
	"""
	cookie = request.cookies.get("token", None);
	token = Utils.get_token(cookie);
	if not token:
		return Utils.make_response({
			'status': 'failure',
			'reason': 'unauthorized'
			}, 403);
	query = "UPDATE rad_users SET blocked = FALSE WHERE id = ?";
	g.cur.execute(query, (id));
	g.cur.commit();
	return Utils.make_response({
		"status": "success"
	}, 200);


if __name__ == "__main__":
	app.run(host="0.0.0.0", port=5000);
