import json
import os
import urllib
from urlparse import parse_qs
import jwkest
from jwkest.jwk import SYMKey
from jwkest.jws import JWS
from mako.lookup import TemplateLookup
from oic.oic import JWT_BEARER
from oic.utils.authn.client import ClientSecretJWT
from oic.utils.authn.client import PrivateKeyJWT
from oic.utils.http_util import Unauthorized
from oic.oauth2 import rndstr
from oic.oauth2 import Client
from oic.oauth2 import AccessTokenRequest
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import rsa_load

__author__ = 'rolandh'

PASSWD = {"user": "hemligt"}

ROOT = '../oidc_example/op1/'
tl = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                    module_directory=ROOT + 'modules',
                    input_encoding='utf-8', output_encoding='utf-8')

_key = rsa_load("%s/certs/mycert.key" % ROOT)

KC_RSA = KeyBundle([{"key": _key, "kty": "RSA", "use": "ver"},
                    {"key": _key, "kty": "RSA", "use": "sig"}])


def create_return_form_env(user, password, query):
    _dict = {
        "login": user,
        "password": password,
        "query": query
    }

    return urllib.urlencode(_dict)


class SRV(object):
    def __init__(self):
        pass


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_1():
    authn = UsernamePasswordMako(None, "login.mako", tl, PASSWD,
                                 "authorization_endpoint")
    assert authn.authenticated_as() is None


def test_2():
    authn = UsernamePasswordMako(None, "login.mako", tl, PASSWD,
                                 "authorization_endpoint")
    resp = authn(query="QUERY")
    print resp.message
    assert 'name="query" value="QUERY"' in resp.message
    assert 'name="login" value=""' in resp.message


def test_3():
    form = create_return_form_env("user", "hemligt", "query=foo")
    srv = SRV()
    srv.symkey = rndstr(16)
    srv.seed = rndstr()
    srv.iv = os.urandom(16)
    srv.cookie_name = "xyzxyz"

    authn = UsernamePasswordMako(srv, "login.mako", tl, PASSWD,
                                 "authorization_endpoint")
    response, success = authn.verify(parse_qs(form))
    assert response.message == "authorization_endpoint?query=foo&upm_answer=true"
    print len(response.headers) == 2
    flag = 0
    for param, val in response.headers:
        if param == "Set-Cookie":
            assert val.startswith('xyzxyz=')
            flag = 1
    assert flag == 1


# def test_4():
#     form = create_return_form_env("user", "hemligt", "QUERY")
#     srv = SRV()
#     srv.symkey = "symkey"
#     srv.seed = rndstr()
#     srv.iv = os.urandom(16)
#     srv.cookie_name = "xyzxyz"
#
#     authn = UsernamePasswordMako(srv, "login.mako", tl, PASSWD,
#                                  "authorization_endpoint")
#     response = authn.verify(parse_qs(form))
#
#     kaka = None
#     for param, val in response.headers:
#         if param == "Set-Cookie":
#             kaka = val
#             break
#
#     print response.headers
#     print kaka
#     print authn.active
#     user = authn.authenticated_as(kaka)
#     assert user == {"uid": "user"}


def test_5():
    form = create_return_form_env("user", "hemligt", "QUERY")
    srv = SRV()
    srv.symkey = rndstr(16)
    srv.seed = rndstr()
    srv.iv = os.urandom(16)
    srv.cookie_name = "xyzxyz"

    authn = UsernamePasswordMako(srv, "login.mako", tl, PASSWD,
                                 "authorization_endpoint")
    response, state = authn.verify(parse_qs(form))

    kaka = ""
    for param, val in response.headers:
        if param == "Set-Cookie":
            kaka = val
            break

    kaka = kaka.replace("1", "x")
    try:
        _ = authn.authenticated_as(kaka)
        assert False
    except Exception:
        assert True


def test_6():
    form = create_return_form_env("user", "secret", "QUERY")
    srv = SRV()
    srv.symkey = rndstr(16)
    srv.seed = rndstr()
    srv.iv = os.urandom(16)
    srv.cookie_name = "xyzxyz"

    authn = UsernamePasswordMako(srv, "login.mako", tl, PASSWD,
                                 "authorization_endpoint")
    response, state = authn.verify(parse_qs(form))
    assert isinstance(response, Unauthorized)


def test_client_secret_jwt():
    cli = Client("Foo")
    cli.token_endpoint = "https://example.com/token"
    cli.client_secret = "foobar"

    csj = ClientSecretJWT(cli)
    cis = AccessTokenRequest()

    http_args = csj.construct(cis, algorithm="HS256")
    print http_args
    assert cis["client_assertion_type"] == JWT_BEARER
    assert "client_assertion" in cis
    cas = cis["client_assertion"]
    header, claim, crypto, header_b64, claim_b64 = jwkest.unpack(cas)
    jso = json.loads(claim)
    assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
    print header
    assert header == {'alg': 'HS256'}

    _rj = JWS()
    info = _rj.verify_compact(cas, [SYMKey(key=cli.client_secret)])

    _dict = json.loads(info)
    assert _eq(_dict.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])


def test_private_key_jwt():
    cli = Client("FOO")
    cli.token_endpoint = "https://example.com/token"
    cli.keyjar[""] = KC_RSA

    cis = AccessTokenRequest()
    pkj = PrivateKeyJWT(cli)
    http_args = pkj.construct(cis, algorithm="RS256")
    assert http_args == {}
    cas = cis["client_assertion"]
    header, claim, crypto, header_b64, claim_b64 = jwkest.unpack(cas)
    jso = json.loads(claim)
    assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
    print header
    assert header == {'alg': 'RS256'}

if __name__ == "__main__":
    test_3()