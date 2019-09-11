import crypto;
from crypto import digest;

import os
from time import time

import numpy as np;

results = [];

IV_SIZE = 16;

for i in range(0, 10000):
	data = os.urandom(1024);
	start = time();
	sha256 = digest.SHA256Digest();
	sha256.digest(data);
	end = time();
	results.append(end-start);

print("Mean: ", np.mean(results));
print("SD: ", np.std(results));

