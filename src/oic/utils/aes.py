#!/usr/bin/env python
from future.utils import tobytes

import os
from base64 import b64decode
from base64 import b64encode

from Cryptodome import Random
from Cryptodome.Cipher import AES
from six import binary_type
from six import indexbytes
from six import text_type

__author__ = 'rolandh'

POSTFIX_MODE = {
    "cbc": AES.MODE_CBC,
    "cfb": AES.MODE_CFB,
    "ecb": AES.MODE_CFB,
}

BLOCK_SIZE = 16


class AESError(Exception):
    pass


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
        raise AESError("Unsupported key length")
    if len(key) != int(bits) >> 3:
        raise AESError("Wrong Key length")

    try:
        return AES.new(tobytes(key), POSTFIX_MODE[cmode], tobytes(iv)), iv
    except KeyError:
        raise AESError("Unsupported chaining mode")


def encrypt(key, msg, iv=None, alg="aes_128_cbc", padding="PKCS#7",
            b64enc=True, block_size=BLOCK_SIZE):
    """
    :param key: The encryption key
    :param iv: init vector
    :param msg: Message to be encrypted
    :param padding: Which padding that should be used
    :param b64enc: Whether the result should be base64encoded
    :param block_size: If PKCS#7 padding which block size to use
    :return: The encrypted message
    """

    if padding == "PKCS#7":
        _block_size = block_size
    elif padding == "PKCS#5":
        _block_size = 8
    else:
        _block_size = 0

    if _block_size:
        plen = _block_size - (len(msg) % _block_size)
        c = chr(plen)
        msg += (c * plen)

    cipher, iv = build_cipher(tobytes(key), iv, alg)
    cmsg = iv + cipher.encrypt(tobytes(msg))
    if b64enc:
        return b64encode(cmsg)
    else:
        return cmsg


def decrypt(key, msg, iv=None, padding="PKCS#7", b64dec=True):
    """
    :param key: The encryption key
    :param iv: init vector
    :param msg: Base64 encoded message to be decrypted
    :return: The decrypted message
    """
    if b64dec:
        data = b64decode(msg)
    else:
        data = msg

    _iv = data[:AES.block_size]
    if iv:
        assert iv == _iv
    cipher, iv = build_cipher(key, iv)
    res = cipher.decrypt(data)[AES.block_size:]
    if padding in ["PKCS#5", "PKCS#7"]:
        res = res[:-indexbytes(res, -1)]
    return res.decode("utf-8")


class AEAD(object):
    """
    Authenticated Encryption with Associated Data Wrapper

    This does encryption and integrity check in one
    operation, so you do not need to combine HMAC + encryption
    yourself.

    :param key: The key to use for encryption.
    :type key: bytes
    :param iv: The initialization vector.
    :type iv: bytes
    :param mode: One of the AEAD available modes.

    Your key and initialization vectors should be created from random bytes
    of sufficient length.

    For the default SIV mode, you need one of:

        - 256-bit key, 128-bit IV to use AES-128
        - 384-bit key, 192-bit IV to use AES-192
        - 512-bit key, 256-bit IV to use AES-256

    """
    def __init__(self, key, iv, mode=AES.MODE_SIV):
        assert isinstance(key, binary_type)
        assert isinstance(iv, binary_type)
        self.key = key
        self.mode = mode
        self.iv = iv
        self.kernel = AES.new(self.key, self.mode, self.iv)

    def add_associated_data(self, data):
        """
        Add data to include in the MAC

        This data is protected by the MAC but not encrypted.

        :param data: data to add in the MAC calculation
        :type data: bytes
        """
        if isinstance(data, text_type):
            data = data.encode('utf-8')
        self.kernel.update(data)

    def encrypt_and_tag(self, cleardata):
        """
        Encrypt the given data

        Encrypts the given data and returns the encrypted
        data and the MAC to later verify and decrypt the data.

        :param cleardata: data to encrypt
        :type cleardata: bytes

        :returns: 2-tuple of encrypted data and MAC
        """
        assert isinstance(cleardata, binary_type)
        return self.kernel.encrypt_and_digest(cleardata)

    def decrypt_and_verify(self, cipherdata, tag):
        """
        Decrypt and verify

        Checks the integrity against the tag and decrypts the
        data. Any associated data used during encryption
        needs to be added before calling this too.

        :param cipherdata: The encrypted data
        :type cipherdata: bytes
        :param tag: The MAC tag
        :type tag: bytes
        """
        assert isinstance(cipherdata, binary_type)
        assert isinstance(tag, binary_type)
        try:
            return self.kernel.decrypt_and_verify(cipherdata, tag)
        except ValueError:
            raise AESError("Failed to verify data")


if __name__ == "__main__":
    key_ = "1234523451234545"  # 16 byte key
    # Iff padded the message doesn't have to be multiple of 16 in length
    msg_ = "ToBeOrNotTobe W.S."
    iv_ = os.urandom(16)
    encrypted_msg = encrypt(key_, msg_, iv_)
    txt = decrypt(key_, encrypted_msg, iv_)
    assert txt == msg_

    encrypted_msg = encrypt(key_, msg_, 0)
    txt = decrypt(key_, encrypted_msg, 0)
    assert txt == msg_
