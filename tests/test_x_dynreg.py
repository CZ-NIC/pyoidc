import json
import os

import pytest

from oic.extension.client import ClientRegistrationError
from oic.extension.message import ClientInfoResponse
from oic.extension.message import RegistrationRequest
from oic.extension.message import make_software_statement
from oic.extension.message import unpack_software_statement
from oic.extension.provider import Provider
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import BearerHeader
from oic.utils.authn.client import ClientSecretBasic
from oic.utils.authn.client import ClientSecretPost
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import Implicit
from oic.utils.http_util import NoContent
from oic.utils.http_util import Response
from oic.utils.http_util import Unauthorized
from oic.utils.keyio import build_keyjar

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "data/keys"))

KEYS = [
    {"type": "RSA", "key": os.path.join(BASE_PATH, "cert.key"),
     "use": ["enc", "sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]


def _eq(l1, l2):
    return set(l1) == set(l2)


class TestSoftwareStatement(object):
    @pytest.fixture(autouse=True)
    def create_provider(self):
        jwks, keyjar, kidd = build_keyjar(KEYS)
        self.keyjar = keyjar
        self.issuer = 'https://fedop.example.org'

    def test_pack(self):
        ss = make_software_statement(self.keyjar, self.issuer,
                                     client_id='ABC 001')
        assert ss
        assert len(ss.split('.')) == 3

    def test_pack_and_unpack(self):
        ss = make_software_statement(self.keyjar, self.issuer,
                                     client_id='ABC 001')

        msg = unpack_software_statement(ss, self.issuer, self.keyjar)
        assert msg
        assert _eq(msg.keys(), ['client_id', 'iat', 'iss', 'exp', 'jti', 'kid'])
        assert msg['client_id'] == 'ABC 001'
        assert msg['iss'] == self.issuer


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        return {"uid": self.user}


class TestProvider(object):
    SERVER_INFO = {
        "version": "3.0",
        "issuer": "https://connect-op.heroku.com",
        "authorization_endpoint": "http://localhost:8088/authorization",
        "token_endpoint": "http://localhost:8088/token",
        "flows_supported": ["code", "token", "code token"],
    }

    CDB = {
        "a1b2c3": {
            "password": "hemligt",
            "client_secret": "drickyoughurt"
        },
        "client1": {
            "client_secret": "hemlighet",
            "redirect_uris": [("http://localhost:8087/authz", None)]
        }
    }

    @pytest.fixture(autouse=True)
    def create_provider(self, session_db_factory):
        authn_broker = AuthnBroker()
        authn_broker.add("UNDEFINED", DummyAuthn(None, "username"))

        self.provider = Provider("pyoicserv",
                                 session_db_factory(
                                     TestProvider.SERVER_INFO["issuer"]),
                                 TestProvider.CDB,
                                 authn_broker, Implicit(),
                                 verify_client,
                                 client_info_url="https://example.com/as",
                                 client_authn_methods={
                                     "client_secret_post": ClientSecretPost,
                                     "client_secret_basic": ClientSecretBasic,
                                     "bearer_header": BearerHeader})

    def test_registration_endpoint(self):
        request = RegistrationRequest(client_name="myself",
                                      redirect_uris=["https://example.com/rp"],
                                      grant_type=['authorization_code',
                                                  'implicit'])
        resp = self.provider.registration_endpoint(request=request.to_json())
        assert isinstance(resp, Response)
        data = json.loads(resp.message)
        assert data["client_name"] == "myself"
        assert _eq(data["redirect_uris"], ["https://example.com/rp"])

        _resp = ClientInfoResponse().from_json(resp.message)
        assert "client_id" in _resp

    def test_registration_uri_error(self):
        args = {
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "client_name": "My Example Client",
            "client_name#ja-Jpan-JP":
                "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "read write dolphin",
            # invalid logo_uri
            "logo_uri": "https://client.example.org/logo.png",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks"
        }

        request = RegistrationRequest(**args)
        resp = self.provider.registration_endpoint(request=request.to_json())
        _resp = ClientRegistrationError().from_json(resp.message)

        assert "error" in _resp
        assert _resp["error"] == "invalid_client_metadata"

    def test_client_registration_utf_8_client_name(self):
        args = {
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "client_name": "My Example Client",
            "client_name#ja-Jpan-JP":
                "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "read write dolphin",
        }

        request = RegistrationRequest(**args)
        resp = self.provider.registration_endpoint(request=request.to_json())
        _resp = ClientInfoResponse().from_json(resp.message)

        assert _resp[
                   "client_name#ja-Jpan-JP"] == "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D"
        assert _resp["client_name"] == "My Example Client"

    def test_client_user_info_get(self):
        args = {
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "client_name": "My Example Client",
            "client_name#ja-Jpan-JP":
                "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "read write dolphin",
        }
        request = RegistrationRequest(**args)
        resp = self.provider.registration_endpoint(request=request.to_json())
        _resp = ClientInfoResponse().from_json(resp.message)

        resp = self.provider.client_info_endpoint(
            "GET",
            environ={"HTTP_AUTHORIZATION": "Bearer %s" % (
                _resp["registration_access_token"],)},
            query="client_id=%s" % _resp["client_id"],
            request=request.to_json())

        _resp_cir = ClientInfoResponse().from_json(resp.message)
        assert _resp == _resp_cir

    def test_client_registration_update(self):
        args = {
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "client_name": "My Example Client",
            "client_name#ja-Jpan-JP":
                "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "read write dolphin",
        }
        request = RegistrationRequest(**args)
        resp = self.provider.registration_endpoint(request=request.to_json(),
                                                   environ={})
        _resp = ClientInfoResponse().from_json(resp.message)

        update = {
            "client_id": _resp["client_id"],
            "client_secret": _resp["client_secret"],
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/alt"],
            "scope": "read write dolphin",
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "client_secret_basic",
            "jwks_uri": "https://client.example.org/my_public_keys.jwks",
            "client_name": "My New Example",
            "client_name#fr": "Mon Nouvel Exemple",
        }
        update_req = RegistrationRequest(**update)
        resp = self.provider.client_info_endpoint(
            request=update_req.to_json(),
            environ={"HTTP_AUTHORIZATION": "Bearer %s" % (
                _resp["registration_access_token"],)},
            method="PUT",
            query="client_id=%s" % _resp["client_id"])

        _resp_up = ClientInfoResponse().from_json(resp.message)
        assert _resp_up["client_id"] == update["client_id"]
        assert _resp_up["client_secret"] == update["client_secret"]
        assert _resp_up["redirect_uris"] == update["redirect_uris"]
        assert _resp_up["scope"] == update["scope"].split()
        assert _resp_up["grant_types"] == update["grant_types"]
        assert _resp_up["token_endpoint_auth_method"] == update[
            "token_endpoint_auth_method"]
        assert _resp_up["jwks_uri"] == update["jwks_uri"]
        assert _resp_up["client_name"] == update["client_name"]
        assert _resp_up["client_name#fr"] == update["client_name#fr"]

    #
    def test_client_registration_delete(self):
        args = {
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "client_name": "My Example Client",
            "client_name#ja-Jpan-JP":
                "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "read write dolphin",
        }
        request = RegistrationRequest(**args)
        resp = self.provider.registration_endpoint(request=request.to_json(),
                                                   environ={})
        _resp = ClientInfoResponse().from_json(resp.message)
        resp = self.provider.client_info_endpoint(
            request=request.to_json(),
            environ={"HTTP_AUTHORIZATION": "Bearer %s" % (
                _resp["registration_access_token"],)},
            method="DELETE",
            query="client_id=%s" % _resp["client_id"])

        assert isinstance(resp, NoContent)

        # A read should fail
        resp = self.provider.client_info_endpoint(
            "",
            environ={"HTTP_AUTHORIZATION": "Bearer %s" % (
                _resp["registration_access_token"],)},
            query="client_id=%s" % _resp["client_id"])

        assert isinstance(resp, Unauthorized)

    def test_client_registration_with_software_statement(self):
        jwks, keyjar, kidd = build_keyjar(KEYS)
        fed_operator = 'https://fedop.example.org'

        self.provider.keyjar[fed_operator] = keyjar['']
        ss = make_software_statement(keyjar, fed_operator, client_id='foxtrot')

        args = {
            "redirect_uris": ["https://client.example.org/callback",
                              "https://client.example.org/callback2"],
            "client_name": "XYZ Service B",
            "token_endpoint_auth_method": "client_secret_basic",
            "scope": "read write dolphin",
            'software_statement': ss
        }
        request = RegistrationRequest(**args)
        resp = self.provider.registration_endpoint(request=request.to_json(),
                                                   environ={})
        cli_resp = ClientInfoResponse().from_json(resp.message)
        assert cli_resp
