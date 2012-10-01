__author__ = 'rohe0002'

from M2Crypto import RSA

from oic.jwt import jwe
from oic.jwt.jwe import rsa_encrypt
from oic.jwt.jwe import rsa_decrypt
from oic.jwt.jwe import encrypt
from oic.jwt.jwe import decrypt

cmk = [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
       206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
       44, 207]

cmk2 = [148, 116, 199, 126, 2, 117, 233, 76, 150, 149, 89, 193, 61, 34, 239,
        226, 109, 71, 59, 160, 192, 140, 150, 235, 106, 204, 49, 176, 68,
        119, 13, 34, 49, 19, 41, 69, 5, 20, 252, 145, 104, 129, 137, 138, 67,
        23, 153, 83, 81, 234, 82, 247, 48, 211, 41, 130, 35, 124, 45, 156,
        249, 7, 225, 168]


# JWE test A.3.1
def test_a31():
    r = jwe.get_cek(cmk)
    x = jwe.hd2ia(r)
    print x
    assert x == [249, 255, 87, 218, 224, 223, 221, 53, 204, 121, 166, 130, 195,
                 184, 50, 69]

# JWE test A.3.2
def test_a32():
    r = jwe.get_cik(cmk)
    x = jwe.hd2ia(r)
    print x
    assert x ==  [218, 209, 130, 50, 169, 45, 70, 214, 29, 187, 123, 20, 3, 158,
                  111, 122, 182, 94, 57, 133, 245, 76, 97, 44, 193, 80, 81, 246,
                  115, 177, 225, 159]

# JWE test A.4.1
def test_a41():
    r = jwe.get_cek(cmk2, length=256)
    x = jwe.hd2ia(r)
    print x
    assert x == [137, 5, 92, 9, 17, 47, 17, 86, 253, 235, 34, 247, 121, 78, 11,
                 144, 10, 172, 38, 247, 108, 243, 201, 237, 95, 80, 49, 150, 116,
                 240, 159, 64]

# JWE test A.4.2
def test_a42():
    r = jwe.get_cik(cmk2, length=256)
    x = jwe.hd2ia(r)
    r = jwe.get_cik(cmk2, round=2, length=256)
    x.extend(jwe.hd2ia(r))
    print x
    assert x == [11, 179, 132, 177, 171, 24, 126, 19, 113, 1, 200, 102, 100, 74,
                 88, 149, 31, 41, 71, 57, 51, 179, 106, 242, 113, 211, 56, 56,
                 37, 198, 57, 17, 149, 209, 221, 113, 40, 191, 95, 252, 142,
                 254, 141, 230, 39, 113, 139, 84, 44, 156, 247, 47, 223, 101,
                 229, 180, 82, 231, 38, 96, 170, 119, 236, 81]


def gen_callback(*args):
    pass

rsa = RSA.gen_key(2048, 65537, gen_callback)
plain = "Now is the time for all good men to come to the aid of their country."

def test_rsa_encrypt_decrypt_rsa_cbc():
    jwt = rsa_encrypt(plain, rsa, alg="RSA1_5", enc="A128CBC", int="HS256")

    msg = rsa_decrypt(jwt, rsa, "private")

    assert msg == plain

def test_rsa_encrypt_decrypt_rsa_oaep_gcm():
    jwt = rsa_encrypt(plain, rsa, alg="RSA-OAEP", enc="A256GCM")

    msg = rsa_decrypt(jwt, rsa, "private")

    assert msg == plain

def test_encrypt_decrypt_rsa_cbc():
    jwt = encrypt(plain, {"rsa":[rsa]}, alg="RSA1_5", enc="A128CBC",
                  context="public", int="HS256")
    msg = decrypt(jwt, {"rsa":[rsa]}, "private")

    assert msg == plain
