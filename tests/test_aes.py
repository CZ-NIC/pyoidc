import os

import pytest

from oic.utils.aes import AEAD
from oic.utils.aes import AESError
from oic.utils.aes import decrypt
from oic.utils.aes import encrypt


def test_encrypt_decrypt():
    key_ = b"1234523451234545"  # 16 byte key
    # Iff padded the message doesn't have to be multiple of 16 in length
    msg_ = "ToBeOrNotTobe W.S."
    iv_ = os.urandom(16)
    encrypted_msg = encrypt(key_, msg_, iv_)
    txt = decrypt(key_, encrypted_msg, iv_)
    assert txt == msg_

    encrypted_msg = encrypt(key_, msg_, 0)
    txt = decrypt(key_, encrypted_msg, 0)
    assert txt == msg_


@pytest.fixture
def aead_key():
    return os.urandom(32)


@pytest.fixture
def aead_iv():
    return os.urandom(16)


@pytest.fixture
def cleartext():
    return b"secret sauce"


def test_AEAD_good(aead_key, aead_iv, cleartext):
    extra = ["some", "extra", "data"]
    k = AEAD(aead_key, aead_iv)
    for d in extra:
        k.add_associated_data(d)
    ciphertext, tag = k.encrypt_and_tag(cleartext)

    # get a fresh AEAD object
    c = AEAD(aead_key, aead_iv)
    for d in extra:
        c.add_associated_data(d)
    cleartext2 = c.decrypt_and_verify(ciphertext, tag)
    assert cleartext2 == cleartext


def test_AEAD_bad_aad(aead_key, aead_iv, cleartext):
    extra = ["some", "extra", "data"]
    k = AEAD(aead_key, aead_iv)
    for d in extra:
        k.add_associated_data(d)
    ciphertext, tag = k.encrypt_and_tag(cleartext)

    # get a fresh AEAD object
    c = AEAD(aead_key, aead_iv)
    # skip one aad item, MAC is wrong now
    for d in extra[:1]:
        c.add_associated_data(d)

    with pytest.raises(AESError):
        c.decrypt_and_verify(ciphertext, tag)
