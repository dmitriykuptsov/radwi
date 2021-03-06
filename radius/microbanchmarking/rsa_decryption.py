import crypto;
from crypto import certs;
from crypto import rsa;
import numpy as np;
import os;
from time import time;

results = [];

certificate = certs.X509v3Certificate.load("../config/certs/certificate.pem");
public_key = certificate.get_public_key_info();
private_key = certs.RSAPrivateKey.load("../config/certs/key.pem").get_key_info();

for i in range(0, 10000):
	data = os.urandom(1000);
	cipher = rsa.RSACrypto();
	ciphertext = cipher.encrypt(data, public_key);
	start = time();
	plaintext = cipher.decrypt(ciphertext, private_key);
	end = time();
	results.append(end-start);

print("Mean: ", np.mean(results));
print("SD: ", np.std(results));