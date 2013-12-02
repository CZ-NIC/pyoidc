#!/usr/bin/env python
import os
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode

__author__ = 'rolandh'

POSTFIX_MODE = {
    "cbc": AES.MODE_CBC,
    "cfb": AES.MODE_CFB,
    "ecb": AES.MODE_CFB,
}


def build_cipher(key, iv, alg="aes_128_cbc"):
    """
    :param key: encryption key
    :param iv: init vector
    :param alg: cipher algorithm
    :return: A Cipher instance
    """
    typ, bits, cmode = alg.split("_")

    if not iv:
        iv = Random.new().read(AES.block_size)
    else:
        assert len(iv) == AES.block_size

    if bits not in ["128", "192", "256"]:
        raise Exception("Unsupported key length")
    try:
        assert len(key) == int(bits) >> 3
    except AssertionError:
        raise Exception("Wrong Key length")

    try:
        return AES.new(key, POSTFIX_MODE[cmode], iv), iv
    except KeyError:
        raise Exception("Unsupported chaining mode")


def encrypt(key, msg, iv=None, alg="aes_128_cbc"):
    """
    :param key: The encryption key
    :param iv: init vector
    :param msg: Message to be encrypted
    :return: The encrypted message base64 encoded
    """

    cipher, iv = build_cipher(key, iv, alg)
    return b64encode(iv + cipher.encrypt(msg))


def decrypt(key, msg, iv=None):
    """
    :param key: The encryption key
    :param iv: init vector
    :param msg: Base64 encoded message to be decrypted
    :return: The decrypted message
    """
    data = b64decode(msg)
    _iv = data[:AES.block_size]
    if iv:
        assert iv == _iv
    cipher, iv = build_cipher(key, iv)
    return cipher.decrypt(data)[AES.block_size:]

if __name__ == "__main__":
    key_ = "1234523451234545"  # 16 byte key
    # Message has to be multiple of 16 in length
    msg_ = "ToBeOrNotTobe WS01234567"
    iv_ = os.urandom(16)
    encrypted_msg = encrypt(key_, msg_, iv_)
    print decrypt(key_, encrypted_msg, iv_)

    encrypted_msg = encrypt(key_, msg_, 0)
    print decrypt(key_, encrypted_msg, 0)