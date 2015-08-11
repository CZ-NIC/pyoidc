import json

import pytest

from oic.utils.http_util import Response, NoContent, Unauthorized
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.client import BearerHeader
from oic.utils.authn.client import ClientSecretPost
from oic.utils.authn.client import ClientSecretBasic
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import Implicit
from oic.utils import sdb
from oic.oauth2.dynreg import Provider
from oic.oauth2.dynreg import RegistrationRequest
from oic.oauth2.dynreg import ClientInfoResponse
from oic.oauth2.dynreg import ClientRegistrationError
from utils_for_tests import _eq


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
    def create_provider(self):
        authn_broker = AuthnBroker()
        authn_broker.add("UNDEFINED", DummyAuthn(None, "username"))

        self.provider = Provider("pyoicserv",
                                 sdb.SessionDB(
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
                                      redirect_uris=["https://example.com/rp"])
        resp = self.provider.registration_endpoint(request.to_json(), {})
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
        resp = self.provider.registration_endpoint(request.to_json(), {})
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
        resp = self.provider.registration_endpoint(request.to_json(), {})
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
        resp = self.provider.registration_endpoint(request.to_json(),
                                                   environ={})
        _resp = ClientInfoResponse().from_json(resp.message)

        resp = self.provider.client_info_endpoint(
            "",
            environ={"HTTP_AUTHORIZATION": "Bearer %s" % (
                _resp["registration_access_token"],)},
            query="client_id=%s" % _resp["client_id"])

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
        resp = self.provider.registration_endpoint(request.to_json(),
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
            update_req.to_json(),
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
        resp = self.provider.registration_endpoint(request.to_json(),
                                                   environ={})
        _resp = ClientInfoResponse().from_json(resp.message)
        resp = self.provider.client_info_endpoint(
            "",
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
