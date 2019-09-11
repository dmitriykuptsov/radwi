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


from utils import Utils;
#from radius import radius;

from eap import eap;
from tls import tls;
import radius;
#from radius import radius;
from radius import radius;
#help(radius);
from binascii import unhexlify;
from binascii import hexlify;

# EAP 1
packet1 = '0bb20422adf91a1f21872515d0aac3f4e200d3ce4fff010203f215c000000a62160300005d020000280303fbccc64be4fc89218948fb05f01ee51568ff75066891d221b4bba48bb4d011c100003d0000000b000a29000a26000a2330820a1f30820607a0030201020209008a1b79901ded25b0300d06092a864886f70d01010b05003081a5310b300906035504061302555a3111300f06035504080c08546173686b656e743111300f06035504070c08546173686b656e7431123010060355040a0c0976697a6c792e6e6574311e301c060355040b0c154e6574776f726b696e67206465706172746d656e743112301006035504030c0976697a6c792e6e65743128302606092a864886f70d0109011619646d4fff010203f215c000000a62160300005d020000280303fbccc64be4fc89218948fb05f01ee51568ff75066891d221b4bba48bb4d011c100003d0000000b000a29000a26000a2330820a1f30820607a0030201020209008a1b79901ded25b0300d06092a864886f70d01010b05003081a5310b300906035504061302555a3111300f06035504080c08546173686b656e743111300f06035504070c08546173686b656e7431123010060355040a0c0976697a6c792e6e6574311e301c060355040b0c154e6574776f726b696e67206465706172746d656e743112301006035504030c0976697a6c792e6e65743128302606092a864886f70d0109011619646d4fff010203f215c000000a62160300005d020000280303fbccc64be4fc89218948fb05f01ee51568ff75066891d221b4bba48bb4d011c100003d0000000b000a29000a26000a2330820a1f30820607a0030201020209008a1b79901ded25b0300d06092a864886f70d01010b05003081a5310b300906035504061302555a3111300f06035504080c08546173686b656e743111300f06035504070c08546173686b656e7431123010060355040a0c0976697a6c792e6e6574311e301c060355040b0c154e6574776f726b696e67206465706172746d656e743112301006035504030c0976697a6c792e6e65743128302606092a864886f70d0109011619646d4fff010203f215c000000a62160300005d020000280303fbccc64be4fc89218948fb05f01ee51568ff75066891d221b4bba48bb4d011c100003d0000000b000a29000a26000a2330820a1f30820607a0030201020209008a1b79901ded25b0300d06092a864886f70d01010b05003081a5310b300906035504061302555a3111300f06035504080c08546173686b656e743111300f06035504070c08546173686b656e7431123010060355040a0c0976697a6c792e6e6574311e301c060355040b0c154e6574776f726b696e67206465706172746d656e743112301006035504030c0976697a6c792e6e65743128302606092a864886f70d0109011619646d5012d84e0a0f237e0aa4cb6fe2555f051993';
rad_packet = radius.RADIUSPacket(unhexlify(packet1));
eap_packet_bytes = Utils.Utils.get_eap_packet(rad_packet);
eap_packet = eap.EAPTTLSPacket(eap_packet_bytes);
print(eap_packet.get_code());
buffer1 = eap_packet.get_bytes_without_header();

# EAP 2
packet2 = '0bb3042230e5960365dad462d84ff33552181d214fff010303ee1540f6f371822b14816fba121bb9b7027e673e2fc32ac2d4ee4f93095a93768354cb144188d8ce2e0a731bf4143a6f9bb9fc70025daa73be32f60c20fc0c9935d935bab17e27916916eec4a26df096355207308953fd15fdb4c7d4c374dd9235db5e9f987d63e2bda8316d0374689f78e0d4d93db5065cd125d4021b31679ec90a8291c34ca247f37f03496c9c0abf4248b34be5e9b013f333fe35b3559cd2bc1b374bea873b4d5c1eeedaa8ee8614b519d01af73c228159629c194a03831172948bb821baf90e41d5e6ccae0d1ff67fd70e96c8cf5bc5f249ed5cbe1981bbe31c0e17cf424f67f159d8cac0df34e43e9df11fba468a46af874fff010303ee1540f6f371822b14816fba121bb9b7027e673e2fc32ac2d4ee4f93095a93768354cb144188d8ce2e0a731bf4143a6f9bb9fc70025daa73be32f60c20fc0c9935d935bab17e27916916eec4a26df096355207308953fd15fdb4c7d4c374dd9235db5e9f987d63e2bda8316d0374689f78e0d4d93db5065cd125d4021b31679ec90a8291c34ca247f37f03496c9c0abf4248b34be5e9b013f333fe35b3559cd2bc1b374bea873b4d5c1eeedaa8ee8614b519d01af73c228159629c194a03831172948bb821baf90e41d5e6ccae0d1ff67fd70e96c8cf5bc5f249ed5cbe1981bbe31c0e17cf424f67f159d8cac0df34e43e9df11fba468a46af874fff010303ee1540f6f371822b14816fba121bb9b7027e673e2fc32ac2d4ee4f93095a93768354cb144188d8ce2e0a731bf4143a6f9bb9fc70025daa73be32f60c20fc0c9935d935bab17e27916916eec4a26df096355207308953fd15fdb4c7d4c374dd9235db5e9f987d63e2bda8316d0374689f78e0d4d93db5065cd125d4021b31679ec90a8291c34ca247f37f03496c9c0abf4248b34be5e9b013f333fe35b3559cd2bc1b374bea873b4d5c1eeedaa8ee8614b519d01af73c228159629c194a03831172948bb821baf90e41d5e6ccae0d1ff67fd70e96c8cf5bc5f249ed5cbe1981bbe31c0e17cf424f67f159d8cac0df34e43e9df11fba468a46af874fff010303ee1540f6f371822b14816fba121bb9b7027e673e2fc32ac2d4ee4f93095a93768354cb144188d8ce2e0a731bf4143a6f9bb9fc70025daa73be32f60c20fc0c9935d935bab17e27916916eec4a26df096355207308953fd15fdb4c7d4c374dd9235db5e9f987d63e2bda8316d0374689f78e0d4d93db5065cd125d4021b31679ec90a8291c34ca247f37f03496c9c0abf4248b34be5e9b013f333fe35b3559cd2bc1b374bea873b4d5c1eeedaa8ee8614b519d01af73c228159629c194a03831172948bb821baf90e41d5e6ccae0d1ff67fd70e96c8cf5bc5f249ed5cbe1981bbe31c0e17cf424f67f159d8cac0df34e43e9df11fba468a46af87501287ca37f3ce6b5942c4ad1321a8507da6';
rad_packet = radius.RADIUSPacket(unhexlify(packet2));
eap_packet_bytes = Utils.Utils.get_eap_packet(rad_packet);
eap_packet = eap.EAPTTLSPacket(eap_packet_bytes);
print(eap_packet.get_code());
buffer2 = eap_packet.get_bytes_without_header();

# EAP 3
packet3 = '0bb403231ce9c153fb7497cb1ae570b2285c035e4fff010402981500ce16dfb69b27f99d091d383ff1ac46623eed7d7d02ebc31ab45146db99607a6b655ff53d97357369e390f2289e91bd5d23a850e87c21757cec210f3745b4837dfc0d1a15404b4daf54b7cdb93d35e4473d48ea89ece77083f4955053053b7b7fa19fb1c5af882207360443035f5ee726efe69734bf108edd4ab324345d9150bb10e8b6882318d3139f6115168995a4153b8fa77304ce7b260580d462266a0fdf20212bd5f57f6a9defdb7fca96818801e4fb012c7ddfdaecef546e0b0b74797252eede6229061c3b88deef0d3cc80be4d4b5b40e32edb5e67204a42c902c7600276478acb382c3813872f2cd98958df355125ea960472c4fff010402981500ce16dfb69b27f99d091d383ff1ac46623eed7d7d02ebc31ab45146db99607a6b655ff53d97357369e390f2289e91bd5d23a850e87c21757cec210f3745b4837dfc0d1a15404b4daf54b7cdb93d35e4473d48ea89ece77083f4955053053b7b7fa19fb1c5af882207360443035f5ee726efe69734bf108edd4ab324345d9150bb10e8b6882318d3139f6115168995a4153b8fa77304ce7b260580d462266a0fdf20212bd5f57f6a9defdb7fca96818801e4fb012c7ddfdaecef546e0b0b74797252eede6229061c3b88deef0d3cc80be4d4b5b40e32edb5e67204a42c902c7600276478acb382c3813872f2cd98958df355125ea960472c4fff010402981500ce16dfb69b27f99d091d383ff1ac46623eed7d7d02ebc31ab45146db99607a6b655ff53d97357369e390f2289e91bd5d23a850e87c21757cec210f3745b4837dfc0d1a15404b4daf54b7cdb93d35e4473d48ea89ece77083f4955053053b7b7fa19fb1c5af882207360443035f5ee726efe69734bf108edd4ab324345d9150bb10e8b6882318d3139f6115168995a4153b8fa77304ce7b260580d462266a0fdf20212bd5f57f6a9defdb7fca96818801e4fb012c7ddfdaecef546e0b0b74797252eede6229061c3b88deef0d3cc80be4d4b5b40e32edb5e67204a42c902c7600276478acb382c3813872f2cd98958df355125ea960472c501289f89c84311d10e9bb90b835ab85d267';
rad_packet = radius.RADIUSPacket(unhexlify(packet3));
eap_packet_bytes = Utils.Utils.get_eap_packet(rad_packet);
eap_packet = eap.EAPTTLSPacket(eap_packet_bytes);
print(eap_packet.get_code());
buffer3 = eap_packet.get_bytes_without_header();
tls_packet = tls.TLSPacket(buffer1 + buffer2 + buffer3);
for record in tls_packet.get_records():
	print(record.get_version());