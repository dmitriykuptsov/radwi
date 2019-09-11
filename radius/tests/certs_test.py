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


import crypto
from crypto import utils;
from crypto import certs;
from Crypto.PublicKey import RSA;
from crypto import rsa;
from binascii import hexlify
from binascii import unhexlify

private_key = certs.RSAPrivateKey.load("../config/certs/key.pem");
encrypted_message = unhexlify("aee89f6c472a60e5f48b415c9897775e6f0211e248b62849f6a75496890bbd97df499ceb9644d021eb6c5b18ace3ae77d8dc79d4f42465124d0dcff03c650d7a103f05e046d5f6a78276b390eef1689a452ace157bc2dae1fe4fcae210fd73db960d95b7029079411e007dbeada920fbe36311ddda5341754bd2f57e46b6f3256017c883ed3ef60e3131da1046a216c9e6c4c5763a0eec03397fe25d5f5c5a36713f28739a6eba524192a5c1d1532a2593d2baa47adfe8399278fbf665036391bfcc2068b579d48894f81c3ce4721cdf8b4facd8a59e180bed32cf3d36b30ba65c00d9a0c88af02761717a1cf3db37738d04c775097265c0c30cd5b7b55ad3f90b7fa126d22ca33403b01a1a88d020cefae4db3374a6941d1bf48e45e8ddf238792968d013ac6686f24524d33612e6be5dc601836f461c18ee58f83e07e8c0b46a556ed818dd5c511fefe2e285fdc0df8bddafef94d67811f7e0fe2d3933b5e968142f8648d00cd1072e5bec040deb53d8f48739ae530a989ee91ae2e117f330afe8631a3ae8ba2df24b71e97fceb28a6fceb796897076d780da22c24ba31b5326825c5ce8caf3127b409ed7918cde6b365d6ff64a80074fa03edd8eaa5bb12311844c6fae56b2fdde1780b9a9439744ee368ef7e1aa970d8487dd26d6e60f8fda76a1c2557a677c7e294748e117fc52c6374ad00f82475d747e9a9ebad366820a77cb3aa504c6853349b3397d5d6d5f10612d286f614e4cd150c85b2e69c37c02f4d48be0a0d287004a656ce5b60941cb414001fe20c7381b2584c18ce917de1ca39f8426d4485f975222aa727668deb407c20e27f5367ab82fed6ca7a0a818e5d49bdab88de4365cb183db43534f1e621e3b33556a094c8aa9ac813cc91b201396ab3ce64b0359c3896594b7c56a0932302dc6f60ef2401336fc58ce955b89ec640769b6079e8377c5a846c5985c747cb0fed2c49516f03fda8cd29187a39abdff1c9448e198cf6d4aa114f8a83475da193a26b5e5929145e311c236c1635e8cc5290f86a779f169f687bf6d3d17484dd09580db09e6cdd2a09153161ea455df46999b5de0f3ff3836d3e4d4e3794440c947b08cfc1640ee57bdaf930ff4677c2971b5a889ec884ea32fbe8e165821bcbcd9626d4d6d9971fd09f2252bc04a68343ff3ec892bb14d85c7cfdf10c24f57465b218e2ef2f23ad2e520f2c6afb34fc92761f6899096dd48642a19dc24bf089f6486198e89749e7fa08f6fbf31f8d320610ba762bd99955fc19464e6402cd391cecec76d877d2a9edf38d3659046afe04a0e7275050d9edeffeaffccef3a960f85cc73b91ebdabe0451c4b9a1f696db92c26e071e8620ca09e21c58058c829ada80b5176ff4fa1dbbb788895d5350d4381812815a4d1d281dade3f00f13e51d732dc402f2e636201615eca5e9805")
print(len(encrypted_message))
pre_master_secret = rsa.RSACrypto().decrypt(encrypted_message, private_key.get_key_info());
print(hexlify(bytearray(pre_master_secret)));

