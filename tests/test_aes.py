import os

from oic.utils.aes import encrypt, decrypt


def test_encrypt_decrypt():
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
