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

# 
# RadWi tables
#

DROP DATABASE IF EXISTS radwi;
CREATE DATABASE radwi;

# Management users
CREATE TABLE radwi.ui_users (
	id INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
	username VARCHAR(100) NOT NULL,
	password VARCHAR(64) NOT NULL
);

# RADIUS users
CREATE TABLE radwi.rad_users (
	id INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
	username VARCHAR(10) NOT NULL,
	password VARCHAR(64) NOT NULL,
	last_auth_attempt DATETIME NOT NULL DEFAULT NOW(),
	blocked BOOLEAN NOT NULL DEFAULT FALSE
);

# RADIUS event log table
CREATE TABLE radwi.rad_events (
	id INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
	user_id INT NOT NULL,
	event VARCHAR(100) NOT NULL,
	event_time DATETIME NOT NULL,
	FOREIGN KEY (user_id)
	REFERENCES rad_users(id)
	ON DELETE CASCADE
);

# Main accounting table
CREATE TABLE radwi.rad_acct (
	id INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
	user_id INT NOT NULL,
	start_time DATETIME NOT NULL,
	end_time DATETIME,
	session_id VARCHAR(50) NOT NULL,
	bytes_transmitted INT NOT NULL DEFAULT 0,
	FOREIGN KEY (user_id)
	REFERENCES rad_users(id)
	ON DELETE CASCADE
);

# Tariff plan table
CREATE TABLE radwi.tariff (
	id INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
	tariff VARCHAR(30) NOT NULL,
	price_per_megabyte DECIMAL NOT NULL, # UZS
	conn_speed_in_kbytes_per_second VARCHAR(10) NOT NULL
);

# User balance
CREATE TABLE radwi.balance (
	id INT AUTO_INCREMENT NOT NULL PRIMARY KEY,
	user_id INT NOT NULL,
	tariff_id INT NOT NULL,
	balance DECIMAL NOT NULL DEFAULT 0, # UZS
	FOREIGN KEY (user_id)
	REFERENCES rad_users(id)
	ON DELETE CASCADE,
	FOREIGN KEY (tariff_id)
	REFERENCES tariff(id)
	ON DELETE CASCADE
);


INSERT INTO radwi.rad_users(username, password) VALUES("dmitriy", SHA2(CONCAT("kedKukTec+", "1234567890"), 256));
INSERT INTO radwi.tariff(tariff, price_per_megabyte, conn_speed_in_kbytes_per_second) VALUES("Byte.io", 10.0, "512k");
INSERT INTO radwi.balance(user_id, tariff_id, balance) VALUES((SELECT id FROM radwi.rad_users WHERE username = "dmitriy"), (SELECT id FROM radwi.tariff WHERE tariff = "Byte.io"), 9000);
