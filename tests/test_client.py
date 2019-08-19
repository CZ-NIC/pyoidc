import base64
import os
from unittest.mock import Mock
from unittest.mock import patch
from urllib.parse import quote_plus

import pytest
from jwkest import as_bytes
from jwkest import b64e
from jwkest.jwk import SYMKey
from jwkest.jwk import rsa_load
from jwkest.jws import JWS
from jwkest.jwt import JWT

from oic.extension.provider import Provider
from oic.oauth2 import Client
from oic.oauth2.grant import Grant
from oic.oauth2.message import AccessTokenRequest
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import ResourceRequest
from oic.oic import JWT_BEARER
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import BearerBody
from oic.utils.authn.client import BearerHeader
from oic.utils.authn.client import ClientSecretBasic
from oic.utils.authn.client import ClientSecretJWT
from oic.utils.authn.client import ClientSecretPost
from oic.utils.authn.client import PrivateKeyJWT
from oic.utils.authn.client import valid_client_info
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import Implicit
from oic.utils.http_util import Response
from oic.utils.keyio import KeyBundle

BASE_PATH = os.path.abspath(os.path.dirname(__file__))


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        return {"uid": self.user}


def _eq(l1, l2):
    return set(l1) == set(l2)


@pytest.fixture
def client():
    cli = Client(client_id="A", config={"issuer": "https://example.com/as"})
    cli.client_secret = "boarding pass"
    return cli


class TestClientSecretBasic(object):
    def test_construct(self, client):
        cis = AccessTokenRequest(code="foo", redirect_uri="http://example.com")

        csb = ClientSecretBasic(client)
        http_args = csb.construct(cis)
        cred = "{}:{}".format(quote_plus("A"), quote_plus("boarding pass"))
        assert http_args == {
            "headers": {
                "Authorization": "Basic {}".format(
                    base64.b64encode(cred.encode("utf-8")).decode("utf-8")
                )
            }
        }

    def test_does_not_remove_padding(self):
        cis = AccessTokenRequest(code="foo", redirect_uri="http://example.com")

        csb = ClientSecretBasic(None)
        http_args = csb.construct(cis, user="ab", password="c")

        assert http_args["headers"]["Authorization"].endswith("==")


class TestBearerHeader(object):
    def test_construct(self, client):
        request_args = {"access_token": "Sesame"}
        bh = BearerHeader(client)
        http_args = bh.construct(request_args=request_args)

        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_http_args(self, client):
        request_args = {"access_token": "Sesame"}
        bh = BearerHeader(client)
        http_args = bh.construct(request_args=request_args, http_args={"foo": "bar"})

        assert _eq(http_args.keys(), ["foo", "headers"])
        assert http_args["headers"] == {"Authorization": "Bearer Sesame"}

    def test_construct_with_headers(self, client):
        request_args = {"access_token": "Sesame"}

        bh = BearerHeader(client)
        http_args = bh.construct(
            request_args=request_args, http_args={"headers": {"x-foo": "bar"}}
        )

        assert _eq(http_args.keys(), ["headers"])
        assert _eq(http_args["headers"].keys(), ["Authorization", "x-foo"])
        assert http_args["headers"]["Authorization"] == "Bearer Sesame"

    def test_construct_with_resource_request(self, client):
        bh = BearerHeader(client)
        cis = ResourceRequest(access_token="Sesame")

        http_args = bh.construct(cis)

        assert "access_token" not in cis
        assert http_args == {"headers": {"Authorization": "Bearer Sesame"}}

    def test_construct_with_token(self, client):
        resp1 = AuthorizationResponse(code="auth_grant", state="state")
        client.parse_response(
            AuthorizationResponse, resp1.to_urlencoded(), "urlencoded"
        )
        resp2 = AccessTokenResponse(
            access_token="token1", token_type="Bearer", expires_in=0, state="state"
        )
        client.parse_response(AccessTokenResponse, resp2.to_urlencoded(), "urlencoded")

        http_args = BearerHeader(client).construct(ResourceRequest(), state="state")
        assert http_args == {"headers": {"Authorization": "Bearer token1"}}


class TestBearerBody(object):
    def test_construct_with_request_args(self, client):
        request_args = {"access_token": "Sesame"}
        cis = ResourceRequest()
        http_args = BearerBody(client).construct(cis, request_args)

        assert cis["access_token"] == "Sesame"
        assert http_args is None

    def test_construct_with_state(self, client):
        resp = AuthorizationResponse(code="code", state="state")
        grant = Grant()
        grant.add_code(resp)
        atr = AccessTokenResponse(
            access_token="2YotnFZFEjr1zCsicMWpAA",
            token_type="example",
            refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
            example_parameter="example_value",
            scope=["inner", "outer"],
        )
        grant.add_token(atr)
        client.grant["state"] = grant

        cis = ResourceRequest()
        http_args = BearerBody(client).construct(cis, {}, state="state", scope="inner")
        assert cis["access_token"] == "2YotnFZFEjr1zCsicMWpAA"
        assert http_args is None

    def test_construct_with_request(self, client):
        resp1 = AuthorizationResponse(code="auth_grant", state="state")
        client.parse_response(
            AuthorizationResponse, resp1.to_urlencoded(), "urlencoded"
        )
        resp2 = AccessTokenResponse(
            access_token="token1", token_type="Bearer", expires_in=0, state="state"
        )
        client.parse_response(AccessTokenResponse, resp2.to_urlencoded(), "urlencoded")

        cis = ResourceRequest()
        BearerBody(client).construct(cis, state="state")

        assert "access_token" in cis
        assert cis["access_token"] == "token1"


class TestClientSecretPost(object):
    def test_construct(self, client):
        cis = AccessTokenRequest(code="foo", redirect_uri="http://example.com")
        csp = ClientSecretPost(client)
        http_args = csp.construct(cis)

        assert cis["client_id"] == "A"
        assert cis["client_secret"] == "boarding pass"
        assert http_args is None

        cis = AccessTokenRequest(code="foo", redirect_uri="http://example.com")
        http_args = csp.construct(cis, {}, http_args={"client_secret": "another"})
        assert cis["client_id"] == "A"
        assert cis["client_secret"] == "another"
        assert http_args == {}


class TestPrivateKeyJWT(object):
    def test_construct(self, client):
        _key = rsa_load(os.path.join(BASE_PATH, "data/keys/rsa.key"))
        kc_rsa = KeyBundle(
            [
                {"key": _key, "kty": "RSA", "use": "ver"},
                {"key": _key, "kty": "RSA", "use": "sig"},
            ]
        )
        client.keyjar[""] = kc_rsa
        client.token_endpoint = "https://example.com/token"
        client.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }
        cis = AccessTokenRequest()
        pkj = PrivateKeyJWT(client)
        http_args = pkj.construct(cis, algorithm="RS256", authn_endpoint="token")
        assert http_args == {}
        cas = cis["client_assertion"]
        _jwt = JWT().unpack(cas)
        jso = _jwt.payload()
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert _jwt.headers == {"alg": "RS256"}
        assert jso["aud"] == [client.provider_info["token_endpoint"]]


class TestClientSecretJWT_TE(object):
    def test_client_secret_jwt(self, client):
        client.token_endpoint = "https://example.com/token"
        client.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }

        csj = ClientSecretJWT(client)
        cis = AccessTokenRequest()

        csj.construct(cis, algorithm="HS256", authn_endpoint="token")
        assert cis["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in cis
        cas = cis["client_assertion"]
        _jwt = JWT().unpack(cas)
        jso = _jwt.payload()
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert _jwt.headers == {"alg": "HS256"}

        _rj = JWS()
        info = _rj.verify_compact(cas, [SYMKey(k=b64e(as_bytes(client.client_secret)))])

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info["aud"] == [client.provider_info["token_endpoint"]]


class TestClientSecretJWT_UI(object):
    def test_client_secret_jwt(self, client):
        client.token_endpoint = "https://example.com/token"
        client.provider_info = {
            "issuer": "https://example.com/",
            "token_endpoint": "https://example.com/token",
        }

        csj = ClientSecretJWT(client)
        cis = AccessTokenRequest()

        csj.construct(cis, algorithm="HS256", authn_endpoint="userinfo")
        assert cis["client_assertion_type"] == JWT_BEARER
        assert "client_assertion" in cis
        cas = cis["client_assertion"]
        _jwt = JWT().unpack(cas)
        jso = _jwt.payload()
        assert _eq(jso.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert _jwt.headers == {"alg": "HS256"}

        _rj = JWS()
        info = _rj.verify_compact(cas, [SYMKey(k=b64e(as_bytes(client.client_secret)))])

        assert _eq(info.keys(), ["aud", "iss", "sub", "jti", "exp", "iat"])
        assert info["aud"] == [client.provider_info["issuer"]]


class TestValidClientInfo(object):
    @patch("oic.utils.authn.client.utc_time_sans_frac", Mock(return_value=123456))
    def test_valid_client_info(self):
        # Expiration time missing or 0, client_secret never expires
        assert valid_client_info({})
        assert valid_client_info({"client_id": "test", "client_secret": "secret"})
        assert valid_client_info({"client_secret_expires_at": 0})
        # Expired secret
        assert valid_client_info({"client_secret_expires_at": 1}) is not True
        assert (
            valid_client_info({"client_id": "test", "client_secret_expires_at": 123455})
            is not True
        )
        # Valid secret
        assert valid_client_info({"client_secret_expires_at": 123457})
        assert valid_client_info(
            {"client_id": "test", "client_secret_expires_at": 123457}
        )


class TestPKCE(object):
    def test_pkce_create(self):
        _cli = Client(config={"code_challenge": {"method": "S256", "length": 64}})
        args, cv = _cli.add_code_challenge()
        assert args["code_challenge_method"] == "S256"
        assert _eq(list(args.keys()), ["code_challenge_method", "code_challenge"])

    def test_pkce_verify_256(self, session_db_factory):
        _cli = Client(config={"code_challenge": {"method": "S256", "length": 64}})
        args, cv = _cli.add_code_challenge()

        authn_broker = AuthnBroker()
        authn_broker.add("UNDEFINED", DummyAuthn(None, "username"))
        _prov = Provider(
            "as",
            session_db_factory("https://connect-op.heroku.com"),
            {},
            authn_broker,
            Implicit(),
            verify_client,
        )

        assert _prov.verify_code_challenge(cv, args["code_challenge"]) is True
        assert _prov.verify_code_challenge(cv, args["code_challenge"], "S256") is True
        resp = _prov.verify_code_challenge("XXX", args["code_challenge"])
        assert isinstance(resp, Response)
        assert resp.info()["status_code"] == 401

    def test_pkce_verify_512(self, session_db_factory):
        _cli = Client(config={"code_challenge": {"method": "S512", "length": 96}})
        args, cv = _cli.add_code_challenge()

        authn_broker = AuthnBroker()
        authn_broker.add("UNDEFINED", DummyAuthn(None, "username"))
        _prov = Provider(
            "as",
            session_db_factory("https://connect-op.heroku.com"),
            {},
            authn_broker,
            Implicit(),
            verify_client,
        )

        assert _prov.verify_code_challenge(cv, args["code_challenge"], "S512") is True
        resp = _prov.verify_code_challenge("XXX", args["code_challenge"])
        assert isinstance(resp, Response)
        assert resp.info()["status_code"] == 401
