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
	Main configuration file for the Web server
"""
config = {
	"MAX_SESSION_DURATION_IN_SECONDS": 24*60*60,
	"PASSWORD_SALT": "gligoofDapt6",
	"DB_USER": "root",
	"DB_PASSWORD": "root",
	"DB": "radwi",
	"DB_HOST": "localhost",
	"SERVER_NONCE": "SfJ#`.sK1KE#U0Xw8nZ\n]5pEyHyfixYs;MuL-ZBz9mG>o/9\}{OCcU?-b7Ap~:B",
	"MASTER_SECRET": "?zi]P'mzx//U`)t.>X7_\\$H>x!Zz'b^ax6i&BNIjk.^>[Ybv23l7bd8\a,dZXuD",
	"VOUCHER_USERNAME_LENGTH": 8,
	"VOUCHER_PASSWORD_LENGTH": 8
}
