import base64
from io import BytesIO
import json
import os
from urllib.parse import urlparse, parse_qsl
from jwkest.jws import JWSig, JWS
import pytest
from time import time
from signed_http_req import sign_http
from oic.oauth2 import rndstr
from oic.oic.consumer import Consumer
from oic.oic.message import AuthorizationResponse, UserInfoRequest, \
    AccessTokenRequest, AccessTokenResponse, AuthorizationRequest
from oic.oic.pop.PoPProvider import PoPProvider
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import AuthzHandling
from oic.utils.keyio import keybundle_from_local_file, KeyJar
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo

HOST = "oidc.example.com"
ISSUER = "https://{}".format(HOST)
CDB = {
    "client1": {
        "client_secret": "drickyoghurt",
        "redirect_uris": [("http://localhost:8087/authz", None)]
    }
}
USERDB = {
    "username": {
        "name": "Linda Lindgren",
        "nickname": "Linda",
        "email": "linda@example.com",
        "verified": True,
        "sub": "username"
    }
}

PROVIDER_RSA = keybundle_from_local_file(
    "/Users/regu0004/dev/pyoidc/tests/data/keys/cert.key",
    "RSA", ["ver", "sig"])
PROVIDER_KEYJAR = KeyJar()
PROVIDER_KEYJAR[""] = PROVIDER_RSA

CLIENT_RSA = keybundle_from_local_file(
    "/Users/regu0004/dev/pyoidc/tests/data/keys/rsa.key",
    "RSA", ["ver", "sig"])
CLIENT_KEYJAR = KeyJar()
CLIENT_KEYJAR[""] = CLIENT_RSA


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie == "FAIL":
            return None, 0
        else:
            return {"uid": self.user}, time()


# AUTHN = UsernamePasswordMako(None, "login.mako", tl, PASSWD, "authenticated")
AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))

TEST_BODY = "abc"
ENVIRON = {
    'HTTP_USER_AGENT': 'python-requests/2.7.0 CPython/3.4.3 Darwin/14.1.0',
    'HTTP_HOST': HOST, 'PATH_INFO': '/userinfo',
    'CONTENT_LENGTH': len(TEST_BODY.encode("utf-8")),
    'CONTENT_TYPE': 'application/x-www-form-urlencoded',
    'HTTP_ACCEPT_ENCODING': 'gzip, deflate', 'QUERY_STRING': 'foo=bar',
    'HTTPS': 'on',
    'REQUEST_METHOD': 'POST', 'HTTP_ACCEPT': '*/*',
    'HTTP_CONNECTION': 'keep-alive', 'REQUEST_URI': '/userinfo',
    'wsgi.input': BytesIO(TEST_BODY.encode("utf-8"))}


class TestPoPProvider(object):
    @pytest.fixture(autouse=True)
    def create_provider(self):
        self.provider = PoPProvider("pyoicserv", SessionDB(ISSUER),
                                    CDB, AUTHN_BROKER, UserInfo(USERDB),
                                    AuthzHandling(), verify_client, rndstr(16),
                                    keyjar=PROVIDER_KEYJAR)
        self.provider.baseurl = "https://localhost:8080/provider"

    def test_parse_request(self):
        request = self.provider.parse_request(ENVIRON)

        assert request["host"] == HOST
        assert request["body"] == TEST_BODY
        assert request["method"] == ENVIRON["REQUEST_METHOD"]
        assert request["path"] == ENVIRON["PATH_INFO"]
        assert request["query"] == dict(parse_qsl(ENVIRON["QUERY_STRING"]))
        assert request["headers"] == {"Host": ENVIRON["HTTP_HOST"],
                                      "User-Agent": ENVIRON["HTTP_USER_AGENT"],
                                      "Content-Length": ENVIRON[
                                          "CONTENT_LENGTH"],
                                      "Accept": ENVIRON["HTTP_ACCEPT"],
                                      "Content-Type": ENVIRON["CONTENT_TYPE"],
                                      "Connection": ENVIRON["HTTP_CONNECTION"],
                                      "Accept-Encoding": ENVIRON[
                                          "HTTP_ACCEPT_ENCODING"]}

    def test_token_endpoint(self):
        atr = self._token_req(self._authz_req())
        assert atr["token_type"] == "pop"

        access_token = atr["access_token"]
        unpacked_at = JWS().verify_compact(access_token,
                                           PROVIDER_KEYJAR.get_verify_key(
                                               owner=""))
        assert unpacked_at["cnf"]["jwk"] == self._get_rsa_jwk()

    def test_userinfo_endpoint(self, monkeypatch):
        access_token = self._token_req(self._authz_req())["access_token"]
        bearer_header = "Bearer {}".format(access_token)
        signature = sign_http(CLIENT_KEYJAR.get_signing_key(owner="")[0],
                              "RS256",
                              ENVIRON["REQUEST_METHOD"],
                              HOST, "/userinfo",
                              req_header=dict(
                                  [("Authorization", bearer_header)]))
        body = "http_signature={}".format(signature).encode("utf-8")
        monkeypatch.setitem(ENVIRON, "HTTP_AUTHORIZATION", bearer_header)
        monkeypatch.setitem(ENVIRON, "wsgi.input", BytesIO(body))
        monkeypatch.setitem(ENVIRON, "CONTENT_LENGTH", len(body))

        resp = self.provider.userinfo_endpoint(
            self.provider.parse_request(ENVIRON))
        userinfo = json.loads(resp.message)
        assert userinfo["nickname"] == USERDB["username"]["nickname"]
        assert userinfo["name"] == USERDB["username"]["name"]
        assert userinfo["sub"]

    def _authz_req(self):
        req_args = {"scope": ["openid", "profile"],
                    "redirect_uri": "http://localhost:8087/authz",
                    "response_type": ["code"],
                    "client_id": "client1"
                    }
        areq = AuthorizationRequest(**req_args)
        resp = self.provider.authorization_endpoint(areq.to_urlencoded())

        return AuthorizationResponse().deserialize(
            urlparse(resp.message).query, "urlencoded")

    def _token_req(self, authz_resp):
        pop_key = base64.urlsafe_b64encode(
            json.dumps(self._get_rsa_jwk()).encode("utf-8")).decode("utf-8")
        areq = AccessTokenRequest(code=authz_resp["code"],
                                  redirect_uri="http://localhost:8087/authz",
                                  client_id="client1",
                                  client_secret="drickyoghurt",
                                  token_type="pop",
                                  key=pop_key)
        resp = self.provider.token_endpoint(request=areq.to_urlencoded(),
                                            request_method="POST")
        return AccessTokenResponse().deserialize(resp.message, "json")

    def _get_rsa_jwk(self):
        jwk = CLIENT_KEYJAR.get_verify_key(owner="")[0].serialize()
        for k, v in jwk.items():
            if isinstance(v, bytes):
                jwk[k] = v.decode("utf-8")

        return jwk
