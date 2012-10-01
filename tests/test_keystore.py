__author__ = 'rohe0002'

from oic.utils.keystore import KeyStore

def test_init_1():
    keystore = KeyStore(None)

def test_init_2():
    #key, type, usage, owner
    jwt_keys = [["foobar","hmac", "sig", "."]]

    keystore = KeyStore(None, jwt_keys)

    skeys = keystore.get_sign_key()

    assert skeys == {'hmac': ['foobar']}

    skeys = keystore.get_sign_key("hmac")

    assert skeys == ['foobar']

def test_3():
    jwt_keys = [["foobar","hmac", "sig", "."]]
    keystore = KeyStore(None, jwt_keys)

    keystore.set_verify_key("xyz", owner="http://example.com/")

    skeys = keystore.get_sign_key("hmac")

    assert skeys == ['foobar']

    skeys = keystore.get_verify_key("hmac", "http://example.com/")

    assert skeys == ['xyz']

    skeys = keystore.get_sign_key(owner="http://example.com/")

    assert skeys == {}

def test_key_export():
    keystore = KeyStore(None)
    part,res = keystore.key_export("http://www.example.com/as", "static",
                                   "keys", sig={"format":"jwk", "alg":"rsa"})

    print part
    assert part.scheme == "http"
    assert part.netloc == "www.example.com"
    assert part.path == "/as"
    print res
    assert res.keys() == ["jwk_url"]
    url = res["jwk_url"]
    assert url == 'http://www.example.com/as/static/jwk.json'

    print keystore.crypt.issuer_keys[""]
    assert keystore.get_sign_key("rsa")