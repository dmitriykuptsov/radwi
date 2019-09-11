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

class BitVector():
	"""
	Bitvector operations
	"""
	@staticmethod
	def _xor(a, b):
		"""
		Computes bitwise XOR (or bitwise addition modulo 2)
		and returns result as a new array
		"""
		c = [0] * len(a);
		for i in range(0, len(a)):
			c[i] = a[i] ^ b[i];
		return c
	@staticmethod
	def _or(a, b):
		"""
		Performs bitwise OR operation
		"""
		c = [0] * len(a);
		for i in range(0, len(a)):
			c[i] = a[i] | b[i];
		return c
	@staticmethod
	def _and(a, b):
		"""
		Performs bitwise AND operation
		"""
		c = [0] * len(a);
		for i in range(0, len(a)):
			c[i] = a[i] & b[i];
		return c
	@staticmethod
	def _concat(a, b):
		"""
		Concatenates two arrays
		"""
		return a + b
