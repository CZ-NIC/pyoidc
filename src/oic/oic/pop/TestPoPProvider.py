from io import BytesIO
import os
from urllib.parse import urlparse
import pytest
from time import time
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

ISSUER = "https://oidc.excample.com"
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

KC_RSA = keybundle_from_local_file(
    "/Users/regu0004/dev/pyoidc/tests/data/keys/rsa.key",
    "RSA", ["ver", "sig"])

KEYJAR = KeyJar()
KEYJAR[""] = KC_RSA


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
    'HTTP_HOST': 'localhost:8080', 'PATH_INFO': '/userinfo',
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
                                    keyjar=KEYJAR)

    def test_parse_request(self):
        request = self.provider.parse_request(ENVIRON)

        assert request["host"] == "localhost:8080"
        assert request["body"] == TEST_BODY
        assert request["method"] == "POST"
        assert request["path"] == "/userinfo"
        assert request["query"] == {"foo": "bar"}
        assert request["headers"] == {"Host": ENVIRON["HTTP_HOST"],
                                      "User-Agent": ENVIRON["HTTP_USER_AGENT"],
                                      "Content-Length": ENVIRON[
                                          "CONTENT_LENGTH"],
                                      "Accept": ENVIRON["HTTP_ACCEPT"],
                                      "Content-Type": ENVIRON["CONTENT_TYPE"],
                                      "Connection": ENVIRON["HTTP_CONNECTION"],
                                      "Accept-Encoding": ENVIRON[
                                          "HTTP_ACCEPT_ENCODING"]}

    def test_userinfo_endpoint(self, monkeypatch):
        access_token = self._create_access_token_with_provider()
        body = "access_token={}".format(access_token).encode("utf-8")
        monkeypatch.setitem(ENVIRON, "wsgi.input", BytesIO(body))
        monkeypatch.setitem(ENVIRON, "CONTENT_LENGTH", len(body))

        resp = self.provider.userinfo_endpoint(
            self.provider.parse_request(ENVIRON))
        print(resp)

    def _create_access_token_with_provider(self):
        req_args = {"scope": ["openid"],
                    "redirect_uri": "http://localhost:8087/authz",
                    "response_type": ["code"],
                    "client_id": "client1"
                    }
        areq = AuthorizationRequest(**req_args)
        resp = self.provider.authorization_endpoint(areq.to_urlencoded())

        ar = AuthorizationResponse().deserialize(
            urlparse(resp.message).query, "urlencoded")

        # Construct Access token request
        areq = AccessTokenRequest(code=ar["code"],
                                  redirect_uri="http://localhost:8087/authz",
                                  client_id="client1",
                                  client_secret="drickyoghurt")
        resp = self.provider.token_endpoint(request=areq.to_urlencoded(),
                                            request_method="POST")
        atr = AccessTokenResponse().deserialize(resp.message, "json")

        return atr["access_token"]
