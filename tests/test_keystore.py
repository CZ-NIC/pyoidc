__author__ = 'rohe0002'

from oic.oauth2 import KeyStore

def test_init_1():
    keystore = KeyStore(None)

def test_init_2():
    #key, type, usage, owner
    jwt_keys = [["foobar","hmac", "sign", "."]]

    keystore = KeyStore(None, jwt_keys)

    skeys = keystore.get_sign_key()

    assert skeys == {'hmac': ['foobar']}

    skeys = keystore.get_sign_key("hmac")

    assert skeys == ['foobar']

def test_3():
    jwt_keys = [["foobar","hmac", "sign", "."]]
    keystore = KeyStore(None, jwt_keys)

    keystore.set_verify_key("xyz", owner="http://example.com/")

    skeys = keystore.get_sign_key("hmac")

    assert skeys == ['foobar']

    skeys = keystore.get_verify_key("hmac", "http://example.com/")

    assert skeys == ['xyz']

    skeys = keystore.get_sign_key(owner="http://example.com/")

    assert skeys == {}