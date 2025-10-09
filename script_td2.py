import os, hashlib, binascii, requests
entropy = os.urandom(16)
print("Entropy (hex):", entropy.hex())

hash_ = hashlib.sha256(entropy).digest()
ENT = len(entropy) * 8
CS = ENT // 32
entropy_bits = bin(int.from_bytes(entropy, 'big'))[2:].zfill(ENT)
hash_bits = bin(int.from_bytes(hash_, 'big'))[2:].zfill(256)
checksum_bits = hash_bits[:CS]
bits = entropy_bits + checksum_bits

wordlist_url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
try:
	wordlist = requests.get(wordlist_url, timeout=10).text.splitlines()
except Exception as e:
	raise SystemExit(f"Failed to download wordlist: {e}")

chunks = [bits[i:i+11] for i in range(0, len(bits), 11)]
indexes = [int(chunk, 2) for chunk in chunks]
mnemonic_words = [wordlist[index] for index in indexes]
mnemonic_phrase = " ".join(mnemonic_words)
print("Mnemonic phrase 12 words:")
print(mnemonic_phrase)

