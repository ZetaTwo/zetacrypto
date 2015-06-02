import base64, binascii, string, itertools, math
from collections import Counter
from Crypto.Cipher import AES

## Common

# Constants
BYTE_MAX = 256
INF = 1<<63

#Hex string <-> ASCII string
a = "deadbeef"
b = a.decode("hex")
c = b.encode("hex")
assert(a==c)

#Hex string <-> byte array
a = "deadbeef"
b = bytearray.fromhex(a)
c = binascii.hexlify(b)
assert(a==c)

# ASCII string <-> byte array
a = "abcd"
b = map(ord, a)
c = ''.join(map(chr, b))
assert(a==c)

def readfile(path):
	with open(path, 'r') as datafile:
		res = datafile.read()
	return res

# Printable
def count_printable(seq):
	"""Returns the number of printable ASCII characters in seq"""
	if type(seq) == str:
		seq = map(ord, seq)
	return len(filter(lambda c: c >= 32 and c <= 126, seq))
def is_printable(seq):
	"""Returns true is seq consists soley of printable ASCII characters"""
	return len(seq) == count_printable(seq)

assert is_printable("abc")
assert not is_printable("abc\x10")
assert is_printable(map(ord, "abc"))
assert not is_printable(bytearray.fromhex("deadbeef"))

# Letter count
def levenshtein_swap(seq1, seq2):
	"""Returns the number of pairwise swaps are needed to turn seq1 into seq2"""
	res = 0
	for i1 in range(len(seq1)):
		i2 = seq2.index(seq1[i1])
		res += abs(i1-i2)
	return res/2

assert levenshtein_swap("abcd", "bacd") == 1
assert levenshtein_swap("abcd", "abcd") == 0
assert levenshtein_swap("abcd", "badc") == 2

FREQ_ENGLISH = {'e': 0.12575645,'t': 0.9085226,'a': 0.8000395,'o': 0.7591270,'i': 0.6920007,'n': 0.6903785,'s': 0.6340880,'h': 0.6236609,'r': 0.5959034,'d': 0.4317924,'l': 0.4057231,'u': 0.2841783,'c': 0.2575785,'m': 0.2560994,'f': 0.2350463,'w': 0.2224893,'g': 0.1982677,'y': 0.1900888,'p': 0.1795742,'b': 0.1535701,'v': 0.0981717,'k': 0.0739906,'x': 0.0179556,'j': 0.0145188,'q': 0.0117571,'z': 0.0079130}
def letter_frequency(seq):
	"""Returns a dictionary with the frequencies of letters in the sequence"""
	freq = filter(lambda x: x in string.letters, seq.lower())
	freq = dict(Counter(freq).most_common())
	freq.update(dict((x, 0) for x in filter(lambda x: x not in freq, string.lowercase)))
	return freq

def letter_frequency_rel(seq):
	"""Returns a dictionary with the relative frequency of letters in the sequence"""
	freq = letter_frequency(seq)
	total = len(seq)
	return {k: float(v)/total for k, v in freq.items()}

def index_coincidence(seq):
	"""Returns the index of coincidence for a sequence"""

def hamming_distance_char(seq1, seq2):
	"""Returns the character hamming distance of two sequences of equal length"""
	return sum(map(lambda x: x[0]!=x[1], zip(seq1, seq2)))
assert hamming_distance_char("abc", "abd") == 1

def hamming_weight(number):
	"""Returns the number of bits set in number"""
	return bin(number).count("1")
assert hamming_weight(7) == 3
assert hamming_weight(4) == 1
assert hamming_weight(0) == 0

def hamming_distance_bit(seq1, seq2):
	"""Returns the bit hamming distance of two sequences of equal length"""
	if type(seq1) == str: seq1 = map(ord, seq1)
	if type(seq2) == str: seq2 = map(ord, seq2)
	return sum(map(lambda x: hamming_weight(x[0]^x[1]), zip(seq1, seq2)))
assert hamming_distance_bit("this is a test", "wokka wokka!!!") == 37

def rms_error(dict1, dict2):
	"""Returns the RMS error between two dictionaries with the same keys"""
	assert dict1.keys() == dict2.keys()
	return math.sqrt(sum((x-y)**2 for x,y in zip(dict1.values(), dict2.values()))/len(dict1))
assert rms_error(FREQ_ENGLISH, FREQ_ENGLISH) == 0

# XOR
def xor_seq_byte(seq, key):
	"""Returns seq XOR:ed with single byte key"""
	return map(lambda x: x ^ key, seq)
def xor_seq_key(seq, key):
	"""Returns seq XOR:ed with key repeated to cover all of seq"""
	if type(seq) == str: seq = map(ord, seq)
	if type(key) == str: key = map(ord, key)
	return map(lambda x: x[0]^x[1], zip(itertools.cycle(key), seq))
def find_single_byte_xor_key(seq, printable_threshold=0.85):
	"""Find the most probable single byte XOR key used to encrypt seq"""
	if type(seq) == str: seq = map(ord, seq)
	best_dist = INF
	best_key = 0
	best = "FAIL"
	for key in range(BYTE_MAX):
		m = xor_seq_byte(seq, key)
		m = ''.join(map(chr, m))

		if count_printable(m) < len(m)*printable_threshold:
			continue

		freq = letter_frequency_rel(m)
		dist = rms_error(freq, FREQ_ENGLISH)
		if dist < best_dist:
			best = m
			best_key = key
			best_dist = dist
	return (best, best_key, best_dist)
def find_vigenere_key_len(cipher, mink, maxk):
	"""Returns the most probable keylength in a vigenere based cipher"""
	best_dist = INF
	best_keysize = 0
	for keysize in range(mink,maxk):
		#Average hamming weight over BLOCKS
		dist = 0
		num_blocks = len(cipher)/keysize
		for i in range(num_blocks):
			block1 = cipher[i*keysize:(i+1)*keysize]
			block2 = cipher[(i+1)*keysize:(i+2)*keysize]
			dist += float(hamming_distance_bit(block1, block2))/keysize
		dist /= num_blocks

		#If better, save
		if dist < best_dist:
			best_dist = dist
			best_keysize = keysize
	return best_keysize
def find_vigenere_key(cipher, keylen):
	"""Breaks a vigenere cipher with known keylen"""
	key=[]
	for i in range(keylen):
		_, k, _ = find_single_byte_xor_key(cipher[i::keylen])
		key.append(k)
	return key

## Problem 1
def problem1():
	TARGET = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	DATA = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

	data = bytearray.fromhex(DATA)
	res = base64.b64encode(data)
	print(res == TARGET, res)

## Problem 2
def problem2():
	TARGET = "746865206b696420646f6e277420706c6179"
	KEY = "686974207468652062756c6c277320657965"
	INPUT = "1c0111001f010100061a024b53535009181c"

	res = xor_seq_key(bytearray.fromhex(INPUT), bytearray.fromhex(KEY))
	res = binascii.hexlify(bytearray(res))
	print(TARGET == res, res)

## Problem 3
def problem3():
	INPUT = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	cipher = bytearray.fromhex(INPUT)
	print find_single_byte_xor_key(cipher)

# Problem 4
def problem4():
	with open('4.txt', 'r') as cipherfile:
		best = 'FAIL'
		best_dist = INF
		for hexline in cipherfile:
			byteline = bytearray.fromhex(hexline.strip())
			m, key, dist = find_single_byte_xor_key(byteline)
			if dist < best_dist:
				best = m
				best_dist = dist
		print(best)

# Problem 5
def problem5():
	INPUT = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	KEY = "ICE"
	TARGET = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	m = map(ord, INPUT)
	key = map(ord, KEY)
	res = xor_seq_key(m, key)
	res = binascii.hexlify(bytearray(res))
	print(res == TARGET, res)

# Problem 6
def problem6():
	# Read input
	INPUT = readfile('6.txt')
	cipher = base64.b64decode(INPUT)

	# Decrypt
	keysize = find_vigenere_key_len(cipher, 2, 40)
	print('Keysize', keysize)
	key = find_vigenere_key(cipher, keysize)
	print('Key', ''.join(map(chr, key)))
	m = xor_seq_key(cipher, key)
	m = ''.join(map(chr, m))
	print(m)

# Problem 7
def problem7():
	KEY = "YELLOW SUBMARINE"
	INPUT = base64.b64decode(readfile('7.txt'))
	aes = AES.new(KEY, AES.MODE_ECB)
	m = aes.decrypt(INPUT)
	print(m)

def problem8():
	BLOCK_SIZE = 16
	best = 'FAIL'
	best_count = 0
	best_index = 0
	with open('8.txt') as cipherfile:
		i = 0
		for hexline in cipherfile:
			hexline = hexline.strip()
			byteline = base64.b64decode(hexline)
			blocks = Counter(byteline[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE] for i in range(len(byteline)/BLOCK_SIZE))
			count = blocks.most_common(1)[0][1]
			if count > best_count:
				best_count = count
				best = hexline
				best_index = i
			i+=1
	print(best_index, best_count, best)

#problem1()
#problem2()
#problem3()
#problem4()
#problem5()
#problem6()
#problem7()
problem8()