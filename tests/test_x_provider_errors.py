"""Error responses of oic.extension.provider.Provider (status codes and OAuth error codes)."""

import json

import pytest

from oic.extension.message import TokenIntrospectionRequest
from oic.extension.provider import Provider
from oic.oauth2.message import AccessTokenRequest, AuthorizationRequest
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import Implicit
from oic.utils.http_util import Response

ISSUER = "https://example.com/as"
REDIRECT_URI = "http://example.com/authz"

CDB = {
    "client1": {
        "client_secret": "hemlighet",
        "redirect_uris": [(REDIRECT_URI, None)],
        "token_endpoint_auth_method": "client_secret_post",
        "response_types": ["code"],
    },
}


class DummyAuthn(UserAuthnMethod):
    def authenticated_as(self, cookie=None, **kwargs):
        return {"uid": "username"}, 0


def _assert_error(resp, status_code, error):
    assert isinstance(resp, Response), "expected an error Response, got {!r}".format(resp)
    assert resp.status_code == status_code
    assert json.loads(resp.message)["error"] == error


def _assert_token(resp):
    assert isinstance(resp, Response), "expected a token Response, got {!r}".format(resp)
    assert resp.status_code == 200
    assert "access_token" in json.loads(resp.message)


class TestExtensionProviderErrorResponses:
    @pytest.fixture(autouse=True)
    def create_provider(self, session_db_factory):
        authn_broker = AuthnBroker()
        authn_broker.add("UNDEFINED", DummyAuthn(None))
        self.provider = Provider("as", session_db_factory(ISSUER), CDB, authn_broker, Implicit(), verify_client)

    def _make_code(self):
        authzreq = AuthorizationRequest(
            state="state", redirect_uri=REDIRECT_URI, client_id="client1", response_type=["code"]
        )
        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authzreq)
        code = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": authzreq.to_json(),
            "client_id": "client1",
            "code": code,
            "code_used": False,
            "redirect_uri": REDIRECT_URI,
            "response_type": ["code"],
        }
        return code

    def _token_request(self, code):
        return AccessTokenRequest(
            code=code,
            redirect_uri=REDIRECT_URI,
            client_id="client1",
            client_secret="hemlighet",
            grant_type="authorization_code",
        )

    def _token(self, code):
        return self.provider.token_endpoint(request=self._token_request(code).to_urlencoded())

    def test_code_reuse_returns_400(self):
        # A used code is invalid_grant, HTTP 400 (RFC 6749, section 5.2)
        code =self._make_code()
        _assert_token(self._token(code))

        _assert_error(self._token(code), 400, "invalid_grant")

    def test_unknown_code_in_code_grant_type_returns_400(self):
        # An unknown code is invalid_grant, HTTP 400 (RFC 6749, section 5.2)
        areq = self._token_request("unknown-code")

        _assert_error(self.provider.code_grant_type(areq), 400, "invalid_grant")

    def test_state_mismatch_in_code_grant_type_returns_400(self):
        # code_grant_type answers 401 unauthorized_client; the client is fine, the grant does not match
        code = self._make_code()
        self.provider.sdb.update_by_token(code, "state", "state")
        areq = self._token_request(code)
        areq["state"] = "other_state"

        _assert_error(self.provider.code_grant_type(areq), 400, "invalid_grant")

    def test_redirect_uri_mismatch_in_code_grant_type_returns_400(self):
        # RFC 6749, section 5.2 names a redirect_uri mismatch as invalid_grant
        code = self._make_code()
        areq = self._token_request(code)
        areq["redirect_uri"] = "http://example.com/other"

        _assert_error(self.provider.code_grant_type(areq), 400, "invalid_grant")

    def test_introspection_with_wrong_client_secret_returns_401(self):
        # verify_client raises AuthnFailure, which get_token_info does not catch -> HTTP 500
        req = TokenIntrospectionRequest(token="whatever", client_id="client1", client_secret="wrong")

        resp = self.provider.introspection_endpoint(request=req.to_urlencoded())

        _assert_error(resp, 401, "invalid_client")

    def test_introspection_without_client_authentication_returns_401(self):
        # Failed client authentication is invalid_client, HTTP 401 (RFC 7662, section 2.3)
        req = TokenIntrospectionRequest(token="whatever")

        resp = self.provider.introspection_endpoint(request=req.to_urlencoded())

        _assert_error(resp, 401, "invalid_client")
