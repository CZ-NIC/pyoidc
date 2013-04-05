#!/usr/bin/env python
import os

__author__ = 'rolandh'

import M2Crypto
from base64 import b64encode, b64decode


def AES_build_cipher(key, iv, op=1, alg="aes_128_cbc"):
    """
    :param key: encryption key
    :param iv: init vector
    :param op: key usage - 1 (encryption) or 0 (decryption)
    :param alg: cipher algorithm
    :return: A Cipher instance
    """
    return M2Crypto.EVP.Cipher(alg=alg, key=key, iv=iv, op=op)


def AES_encrypt(key, msg, iv=None):
    """
    :param key: The encryption key
    :param iv: init vector
    :param msg: Message to be encrypted
    :return: The encrypted message base64 encoded
    """

    if iv is None:
        iv = '\0' * 16

    cipher = AES_build_cipher(key, iv, 1)
    v = cipher.update(msg)
    v = v + cipher.final()
    v = b64encode(v)
    return v


def AES_decrypt(key, msg, iv=None):
    """
    :param key: The encryption key
    :param iv: init vector
    :param msg: Base64 encoded message to be decrypted
    :return: The decrypted message
    """
    if iv is None:
        iv = '\0' * 16

    data = b64decode(msg)
    cipher = AES_build_cipher(key, iv, 0)
    v = cipher.update(data)
    v = v + cipher.final()
    return v

if __name__ == "__main__":
    key = "123452345"
    msg = "ToBeOrNotTobe W.S."
    iv = os.urandom(16)
    encrypted_msg = AES_encrypt(key, msg, iv)
    print AES_decrypt(key, encrypted_msg, iv)