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
RADIUS main configuration file
"""

config = {
	"security": {
		"ca_certificate_path": None,
		"certificate_path": "./config/certs/certificate.pem",
		"private_key": "./config/certs/key.pem",
		"radius_master_secret": "secret"
	},
	"networking": {
		"ip": "0.0.0.0",
		"radius_auth_port": 1812,
		"radius_acct_port": 1813,
		"mtu": 1432, # The MTU is computed as follows: TCP/IP MTU - IP header length - UDP header length = 1500 - 60 - 8 = 1432
		"max_eap_packet_size": 1000, # Currently EAP TLS packets should not be grater than 1000 bytes
		"eap_message_attribute_length": 253
	},
	"database": {
		"driver": "mysql", # Database driver: currently only MySQL driver is supported
		"user": "root",
		"password": "root",
		"database": "radwi",
		"host": "localhost",
		"salt": "kedKukTec+"
	}
}
