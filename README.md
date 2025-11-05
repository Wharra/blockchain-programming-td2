# Blockchain-wallet-creation

# Blockchain Programming - TD2

Implementation of BIP 39 (mnemonic phrases) and BIP 32 (hierarchical deterministic wallets) for Bitcoin.

## Files

- `BIP 39.py` : Generates 12-word mnemonic phrases from entropy
- `BIP 32.py` : Implements HD wallet key derivation
- `requirements.txt` : Python dependencies

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### BIP 39 - Mnemonic Generation
```bash
python "BIP 39.py"
```

Generates 128 bits entropy → SHA-256 checksum → 12 words from BIP 39 wordlist.

### BIP 32 - Key Derivation
```bash
python "BIP 32.py"
```

Generates seed → master key → child keys via derivation paths (e.g., `m/0/1/2'`).

## Features

**BIP 39:**
- Random entropy generation
- SHA-256 checksum calculation
- 12-word mnemonic phrase

**BIP 32:**
- Master key from seed (HMAC-SHA512)
- Private to public key (compressed format)
- Child key derivation (normal & hardened)
- Path-based derivation

## Concepts

**BIP 39:** Entropy → checksum → word mapping  
**BIP 32:** Seed → master key → chain code → child keys

## References

- [BIP 39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
- [BIP 32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)

## Security Warning

⚠️ Educational purposes only. Do not use in production. Always protect private keys.
