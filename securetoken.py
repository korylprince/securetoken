import base64
import os
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_key_size = 32 # AES-256
_ts_offset = 0
_ts_size = 8 # uint64
_nonce_offset = _ts_offset + _ts_size
_nonce_size = 12 # NIST recommended nonce size
_cipher_offset = _nonce_offset + _nonce_size
_tag_size = 16
_min_token_size = _ts_size + _nonce_size + _tag_size

def create_key():
    return base64.urlsafe_b64encode(AESGCM.generate_key(bit_length=8*_key_size))

def create_token(plaintext, key):
    # decode key
    _key = base64.urlsafe_b64decode(key)

    # record time
    timestamp = time.time_ns().to_bytes(_ts_size, byteorder="big", signed=False)

    # generate nonce
    nonce = os.urandom(_nonce_size)

    # encrypt plaintext
    aesgcm = AESGCM(_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), timestamp)

    # concatenate token and base64url encode
    return base64.urlsafe_b64encode(timestamp + nonce + ciphertext)

def decrypt_token(token, key, ttl):
    # decode key
    _key = base64.urlsafe_b64decode(key)

    # base64url decode token
    decoded = base64.urlsafe_b64decode(token)

    # check token length
    if len(decoded) < _min_token_size:
        raise Exception("Invalid Token")

    # separate token
    ts_bytes = decoded[_ts_offset:_ts_offset + _ts_size]
    nonce = decoded[_nonce_offset:_nonce_offset + _nonce_size]
    ciphertext = decoded[_cipher_offset:]

    # verify and decrypt
    aesgcm = AESGCM(_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, ts_bytes)

    # check timestamp
    timestamp = int.from_bytes(ts_bytes, byteorder="big", signed=False)
    if ttl != 0 and time.time_ns() - timestamp > ttl:
        raise Exception("Expired Token")

    return plaintext.decode("utf-8")
