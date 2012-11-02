
__author__ = 'rohe0002'

from binascii import hexlify

from jwkest import jwk, jwe
from jwkest.jwk import x509_rsa_loads
from oic.utils.keyio import key_export, KeyJar, KeyChain

def _eq(l1, l2):
    return set(l1) == set(l2)

def test1():
    kj = KeyJar()
    part,res = key_export("http://example.com/keys/", "outbound", "secret",
                          keyjar=kj,
                          sig={"alg":"rsa", "format":["x509", "jwk"]})

    print part
    print res

    cert = "keys/outbound/cert.pem"
    jwk_def = "keys/outbound/jwk.json"

    _ckey = x509_rsa_loads(open(cert).read())

    _jkey = jwk.loads(open(jwk_def).read())[0][1]


    print jwe.hd2ia(hexlify(_ckey.n))
    print jwe.hd2ia(hexlify(_jkey.n))

    assert _ckey.n == _jkey.n

URL = "https://openidconnect.info/jwk/jwk.json"

def test_keyjar_pairkeys():
    ks = KeyJar()
    ks[""] = KeyChain({"hmac": "a1b2c3d4"}, usage=["sig", "ver"])
    ks["http://www.example.org"] = KeyChain({"hmac": "e5f6g7h8"},
                                            usage=["sig", "ver"])
    ks["http://www.example.org"].append(KeyChain({"rsa": "-rsa-key-"},
                                                 usage=["enc", "dec"]))

    ks["http://www.example.org"].append(KeyChain({"rsa": "i9j10k11l12"},
                                                 usage=["sig", "ver"]))

    collection = ks.verify_keys("http://www.example.org")

    assert _eq(collection.keys(), ["hmac", "rsa"])


#def test_keyjar_remove_key():
#    ks = KeyJar()
#    ks.add_key("a1b2c3d4", "hmac", "sig")
#    ks.add_key("a1b2c3d4", "hmac", "ver")
#    ks.add_key("e5f6g7h8", "hmac", "sig", "http://www.example.org")
#    ks.add_key("e5f6g7h8", "hmac", "ver", "http://www.example.org")
#    ks.add_key("-rsa-key-", "rsa", "enc", "http://www.example.org")
#    ks.add_key("-rsa-key-", "rsa", "dec", "http://www.example.org")
#    ks.add_key("i9j10k11l12", "hmac", "sig", "http://www.example.com")
#    ks.add_key("i9j10k11l12", "hmac", "ver", "http://www.example.com")
#
#    coll = ks.keys_by_owner("http://www.example.org")
#    assert _eq(coll.keys(), ["sig", "ver", "enc", "dec"])
#
#    ks.remove_key("-rsa-key-", "http://www.example.org")
#
#    coll = ks.keys_by_owner("http://www.example.org")
#    assert _eq(coll.keys(), ["sig", "ver"])
#
#def test_keyjar_remove_key_usage():
#    ks = KeyStore(None)
#    ks.add_key("a1b2c3d4", "hmac", "sig")
#    ks.add_key("a1b2c3d4", "hmac", "ver")
#    ks.add_key("e5f6g7h8", "hmac", "sig", "http://www.example.org")
#    ks.add_key("e5f6g7h8", "hmac", "ver", "http://www.example.org")
#    ks.add_key("-rsa-key-", "rsa", "enc", "http://www.example.org")
#    ks.add_key("-rsa-key-", "rsa", "dec", "http://www.example.org")
#    ks.add_key("i9j10k11l12", "hmac", "sig", "http://www.example.com")
#    ks.add_key("i9j10k11l12", "hmac", "ver", "http://www.example.com")
#
#    ks.remove_key("-rsa-key-", "http://www.example.org",usage="dec")
#
#    coll = ks.keys_by_owner("http://www.example.org")
#    assert _eq(coll.keys(), ["sig", "ver", "enc"])
#
#def test_keyjar_remove_key_type():
#    ks = KeyStore(None)
#    ks.add_key("a1b2c3d4", "hmac", "sig")
#    ks.add_key("a1b2c3d4", "hmac", "ver")
#    ks.add_key("e5f6g7h8", "hmac", "sig", "http://www.example.org")
#    ks.add_key("e5f6g7h8", "hmac", "ver", "http://www.example.org")
#    ks.add_key("-rsa-key-", "rsa", "enc", "http://www.example.org")
#    ks.add_key("-rsa-key-", "rsa", "dec", "http://www.example.org")
#    ks.add_key("i9j10k11l12", "hmac", "sig", "http://www.example.com")
#    ks.add_key("i9j10k11l12", "hmac", "ver", "http://www.example.com")
#
#    ks.remove_key_type("rsa", "http://www.example.org")
#
#    coll = ks.keys_by_owner("http://www.example.org")
#    assert _eq(coll.keys(), ["sig", "ver"])
#
#KEYSTORE = KeyStore(None)
#KEYSTORE.add_key("a1b2c3d4", "hmac", "sig")
#KEYSTORE.add_key("a1b2c3d4", "hmac", "ver")
#KEYSTORE.add_key("e5f6g7h8", "hmac", "sig", "http://www.example.org")
#KEYSTORE.add_key("e5f6g7h8", "hmac", "ver", "http://www.example.org")
#KEYSTORE.add_key("-rsa-key-", "rsa", "enc", "http://www.example.org")
#KEYSTORE.add_key("-rsa-key-", "rsa", "dec", "http://www.example.org")
#KEYSTORE.add_key("i9j10k11l12", "hmac", "sig", "http://www.example.com")
#KEYSTORE.add_key("i9j10k11l12", "hmac", "ver", "http://www.example.com")
#
#def test_keyjar_collect_keys():
#    col = KEYSTORE.collect_keys("http://www.example.org/oic")
#
#    print col
#    assert col == {'hmac': ['e5f6g7h8', 'a1b2c3d4']}
#
#
#def test_keyjar_contains():
#    assert "http://www.example.org" in KEYSTORE
#    assert "http://www.example.com" in KEYSTORE
#    assert "http://www.example.com/oic" not in KEYSTORE
#
#def test_keyjar_has_key_of_type():
#    assert KEYSTORE.has_key_of_type("http://www.example.org", "sig", "hmac")
#    assert not KEYSTORE.has_key_of_type("http://www.example.org", "sig", "rsa")