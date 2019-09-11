import crypto;
from crypto import aes;

import os
from time import time

import numpy as np;

results = [];

IV_SIZE = 16;

for i in range(0, 10000):
	iv = os.urandom(16);
	data = os.urandom(1024);
	key = os.urandom(32);
	start = time();
	cipher = aes.AESCipher(aes.AES_CBC_MODE, key, iv);
	cipher.encrypt(data);
	end = time();
	results.append(end-start);

print("Mean: ", np.mean(results));
print("SD: ", np.std(results));

