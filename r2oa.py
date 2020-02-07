import sys
import random
from bitstring import BitArray
from utils.r2oa import encode, rule
from pysnark.runtime import snark, PrivVal

@snark
def r2oa(a_uint, b_uint, size):
	rules, steps = [45, 75, 89], 32
	a = BitArray(uint=a_uint.value, length=size.value)
	b = BitArray(uint=b_uint.value, length=size.value)
	a_enc, b_enc = encode(a, b, rules, steps)
	return encode(a, b, rules, steps)

a = BitArray(sys.argv[1].encode('utf-8'))
b = BitArray([random.getrandbits(1) for x in a])
a_uint, b_uint = a.uint, b.uint

print('Calculating R2OA: {} ({}) of size ({})'.format(sys.argv[1], a_uint, len(a)))
print('Using key: {}'.format((b.hex)))
print('-' * 80)

a_enc, b_enc = r2oa(a_uint, b_uint, len(a))
print('Result A:', a_enc)
print('Result B:', b_enc)