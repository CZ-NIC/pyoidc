import json
import logging
import time
from urllib.parse import parse_qs, urlparse

import pytest
from testfixtures import LogCapture

from oic.exception import UnSupported
from oic.oauth2.consumer import Consumer
from oic.oauth2.message import (
    AccessTokenRequest,
    AccessTokenResponse,
    AuthorizationRequest,
    AuthorizationResponse,
    CCAccessTokenRequest,
    Message,
    ROPCAccessTokenRequest,
    TokenErrorResponse,
)
from oic.oauth2.provider import Provider
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import Implicit
from oic.utils.http_util import Response
from oic.utils.sdb import AuthnEvent
from oic.utils.session_backend import DictSessionBackend

CLIENT_CONFIG = {"client_id": "client1", "config": {"issuer": "https://example.com/as"}}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "flow_type": "code",
    "scope": [],
    "response_type": "code",
}

ISSUER = "https://connect-op.heroku.com"
SERVER_INFO = {
    "version": "3.0",
    "issuer": ISSUER,
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    "flows_supported": ["code", "token", "code token"],
}

CDB = {
    "a1b2c3": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        "response_types": ["code", "token"],
        "redirect_uris": [("http://example.com", None)],
    },
    "client1": {
        "client_secret": "hemlighet",
        "redirect_uris": [("http://localhost:8087/authz", None)],
        "token_endpoint_auth_method": "client_secret_post",
        "response_types": ["code", "token"],
    },
    "client2": {
        "client_secret": "verysecret",
        "redirect_uris": [("http://localhost:8087/authz", None)],
        "token_endpoint_auth_method": "client_secret_basic",
        "response_types": ["code", "token"],
    },
}


def _eq(l1, l2):
    return set(l1) == set(l2)


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        return {"uid": self.user}, time.time()


class NoCookieAuthn(DummyAuthn):
    """Authn that doesn't create cookies."""

    def create_cookie(self, value, typ, cookie_name=None, ttl=-1, kill=False):
        pass


def verify_outcome(msg, prefix, lista):
    """Compare message to list of claims: values.

    :param prefix: prefix string
    :param lista: list of claims=value
    :return: list of possible strings
    """
    assert msg.startswith(prefix)
    qsl = ["{}={}".format(k, v[0]) for k, v in parse_qs(msg[len(prefix) :]).items()]
    return set(qsl) == set(lista)


AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))
AUTHN_BROKER2 = AuthnBroker()
AUTHN_BROKER2.add("UNDEFINED", NoCookieAuthn(None, "username"))
# dealing with authorization
AUTHZ = Implicit()


class TestProvider:
    @pytest.fixture(autouse=True)
    def create_provider(self, session_db_factory):
        self.provider = Provider(
            "pyoicserv",
            session_db_factory(ISSUER),
            CDB,
            AUTHN_BROKER,
            AUTHZ,
            verify_client,
            baseurl="https://example.com/as",
        )

    def test_init(self, session_db_factory):
        provider = Provider(
            "pyoicserv",
            session_db_factory(ISSUER),
            CDB,
            AUTHN_BROKER,
            AUTHZ,
            verify_client,
        )
        assert provider

        provider = Provider(
            "pyoicserv",
            session_db_factory(ISSUER),
            CDB,
            AUTHN_BROKER,
            AUTHZ,
            verify_client,
            urlmap={"client1": ["https://example.com/authz"]},
        )
        assert provider.urlmap["client1"] == ["https://example.com/authz"]

    def test_init_capabilities(self, session_db_factory):
        provider = Provider(
            "pyoicserv",
            session_db_factory(ISSUER),
            CDB,
            AUTHN_BROKER,
            AUTHZ,
            verify_client,
            capabilities={
                "grant_types_supported": ["authorization_code"],
                "version": "1.0",
                "response_types_supported": ["code", "token"],
            },
        )
        assert provider
        assert provider.capabilities["version"] == "1.0"
        assert provider.capabilities["grant_types_supported"] == ["authorization_code"]

    def test_providerinfo(self):
        self.provider.baseurl = "http://example.com/path1/path2"
        resp = self.provider.create_providerinfo()
        assert resp.to_dict()["authorization_endpoint"] == "http://example.com/path1/path2/authorization"

    def test_providerinfo_trailing(self):
        self.provider.baseurl = "http://example.com/path1/path2/"
        resp = self.provider.create_providerinfo()
        assert resp.to_dict()["authorization_endpoint"] == "http://example.com/path1/path2/authorization"

    def test_verify_capabilities(self):
        capabilities = {
            "grant_types_supported": ["authorization_code"],
            "version": "3.0",
            "response_types_supported": ["code", "token"],
        }
        assert self.provider.verify_capabilities(capabilities)

    def test_verify_capabilities_mismatch_list(self):
        capabilities = {
            "grant_types_supported": ["authorization_code"],
            "response_types_supported": ["code token"],
        }  # this is not supported
        assert not self.provider.verify_capabilities(capabilities)

    def test_verify_capabilities_mismatch_str(self):
        capabilities = {
            "grant_types_supported": ["authorization_code"],
            "version": "5.0",
        }  # this is not matching
        assert not self.provider.verify_capabilities(capabilities)

    def test_verify_capabilities_missing(self):
        capabilities = {
            "grant_types_supported": ["authorization_code"],
            "str_value": "test",  # this is not supported
            "we_dont_know_this": True,
        }  # this is not supported
        assert not self.provider.verify_capabilities(capabilities)

    def test_authorization_endpoint_faulty_redirect_uri(self):
        bib = {
            "scope": ["openid"],
            "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
            "redirect_uri": "http://localhost:8087/authz",
            # faulty redirect uri
            "response_type": ["code"],
            "client_id": "a1b2c3",
        }

        arq = AuthorizationRequest(**bib)
        resp = self.provider.authorization_endpoint(request=arq.to_urlencoded())
        assert resp.status_code == 400
        msg = json.loads(resp.message)
        assert msg["error"] == "invalid_request"

    def test_authorization_endpoint_wronge_response_mode(self):
        bib = {
            "scope": ["openid"],
            "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
            "redirect_uri": "http://example.com",
            "response_type": ["code"],
            "response_mode": "fragment",
            "client_id": "a1b2c3",
        }

        arq = AuthorizationRequest(**bib)
        resp = self.provider.authorization_endpoint(request=arq.to_urlencoded())
        assert resp.status_code == 400
        msg = json.loads(resp.message)
        assert msg["error"] == "invalid_request"

    def test_authorization_endpoint_faulty_redirect_uri_nwalker(self):
        bib = {
            "scope": ["openid"],
            "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
            "redirect_uri": " https://example.com.evil.com",
            # faulty redirect uri
            "response_type": ["code"],
            "client_id": "a1b2c3",
        }

        arq = AuthorizationRequest(**bib)
        resp = self.provider.authorization_endpoint(request=arq.to_urlencoded())
        assert resp.status_code == 400
        msg = json.loads(resp.message)
        assert msg["error"] == "invalid_request"

    def test_authorization_endpoint_missing_client_id(self):
        # Url encoded request with missing client_id
        arq = (
            "scope=openid&state=id-6da9ca0cc23959f5f33e8becd9b08cae&"
            "redirect_uri=+https%3A%2F%2Fexample.com&response_type=code"
        )
        resp = self.provider.authorization_endpoint(request=arq)
        assert resp.status_code == 400
        msg = json.loads(resp.message)
        assert msg["error"] == "invalid_request"

    def test_authenticated(self):
        _session_db = DictSessionBackend()
        cons = Consumer(
            _session_db,
            client_config=CLIENT_CONFIG,
            server_info=SERVER_INFO,
            **CONSUMER_CONFIG,
        )

        sid, location = cons.begin("http://localhost:8087", "http://localhost:8088/authorization")

        resp = self.provider.authorization_endpoint(urlparse(location).query)
        assert resp.status_code == 303
        resp = urlparse(resp.message).query
        with LogCapture(level=logging.DEBUG) as logcap:
            aresp = cons.handle_authorization_response(query=resp)

        assert isinstance(aresp, AuthorizationResponse)
        assert _eq(aresp.keys(), ["state", "code", "client_id", "iss"])
        assert _eq(
            cons.grant[sid].keys(),
            ["tokens", "code", "exp_in", "seed", "id_token", "grant_expiration_time"],
        )

        state = aresp["state"]
        logcap.check(
            ("oic.oauth2.consumer", "DEBUG", "- authorization - code flow -"),
            (
                "oic.oauth2.consumer",
                "DEBUG",
                f"QUERY: state={state}&code=<REDACTED>&iss=https%3A%2F%2Fexample.com%2Fas&client_id=client1",
            ),
            (
                "oic.oauth2",
                "DEBUG",
                "Initial response parsing => \"{'state': "
                f"'{state}', 'code': "
                "'<REDACTED>', 'iss': 'https://example.com/as', 'client_id': "
                "'client1'}\"",
            ),
            (
                "oic.oauth2",
                "DEBUG",
                "Verify response with {'client_id': 'client1', 'iss': "
                "'https://example.com/as', 'keyjar': <KeyJar(issuers=[])>}",
            ),
        )

    def test_authenticated_token(self):
        _session_db = DictSessionBackend()
        cons = Consumer(
            _session_db,
            client_config=CLIENT_CONFIG,
            server_info=SERVER_INFO,
            **CONSUMER_CONFIG,
        )

        sid, location = cons.begin("http://localhost:8087", "http://localhost:8088/authorization", "token")

        QUERY_STRING = location.split("?")[1]
        resp = self.provider.authorization_endpoint(QUERY_STRING)
        auth_resp = parse_qs(urlparse(resp.message).fragment)

        assert "access_token" in auth_resp
        assert auth_resp["token_type"][0] == "Bearer"

    def test_token_endpoint(self):
        authreq = AuthorizationRequest(state="state", redirect_uri="http://example.com/authz", client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz",
        }

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            redirect_uri="http://example.com/authz",
            client_id="client1",
            client_secret="hemlighet",
            grant_type="authorization_code",
        )
        with LogCapture(level=logging.DEBUG) as logcap:
            self.provider.token_endpoint(request=areq.to_urlencoded())

        logcap.check(
            ("oic.oauth2.provider", "DEBUG", "- token -"),
            (
                "oic.oauth2.provider",
                "DEBUG",
                "token_request: "
                "grant_type=authorization_code&code=<REDACTED>&redirect_uri=http%3A%2F%2Fexample.com%2Fauthz&client_id=client1&client_secret=<REDACTED>",
            ),
            (
                "oic.utils.authn.client",
                "DEBUG",
                "REQ: {'grant_type': 'authorization_code', 'code': '<REDACTED>', "
                "'redirect_uri': 'http://example.com/authz', 'client_id': 'client1', "
                "'client_secret': '<REDACTED>'}",
            ),
            ("oic.utils.authn.client", "DEBUG", "Verified Client ID: client1"),
            (
                "oic.oauth2.provider",
                "DEBUG",
                "AccessTokenRequest: {'grant_type': 'authorization_code', 'code': "
                "'<REDACTED>', 'redirect_uri': 'http://example.com/authz', 'client_id': "
                "'client1', 'client_secret': '<REDACTED>'}",
            ),
            (
                "oic.oauth2.provider",
                "DEBUG",
                "_tinfo: {'oauth_state': 'token', 'sub': 'sub', 'authzreq': '', 'client_id': "
                "'client1', 'code': '<REDACTED>', 'code_used': True, 'redirect_uri': "
                "'http://example.com/authz', 'access_token': '<REDACTED>', "
                "'access_token_scope': '?', 'token_type': 'Bearer', 'refresh_token': "
                "'<REDACTED>'}",
            ),
            (
                "oic.oauth2.provider",
                "DEBUG",
                "AccessTokenResponse: {'access_token': '<REDACTED>', 'token_type': 'Bearer', "
                "'refresh_token': '<REDACTED>'}",
            ),
        )

    def test_token_endpoint_no_cache(self):
        authreq = AuthorizationRequest(state="state", redirect_uri="http://example.com/authz", client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz",
        }

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            redirect_uri="http://example.com/authz",
            client_id="client1",
            client_secret="hemlighet",
            grant_type="authorization_code",
        )
        resp = self.provider.token_endpoint(request=areq.to_urlencoded())
        assert resp.headers == [
            ("Pragma", "no-cache"),
            ("Cache-Control", "no-store"),
            ("Content-type", "application/json"),
        ]

    def test_token_endpoint_unauth(self):
        authreq = AuthorizationRequest(state="state", redirect_uri="http://example.com/authz", client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz",
        }

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            redirect_uri="http://example.com/authz",
            client_id="<REDACTED>",
            client_secret="hemlighet",
            grant_type="authorization_code",
        )

        resp = self.provider.token_endpoint(request=areq.to_urlencoded())
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert _eq(atr.keys(), ["error_description", "error"])

    def test_token_endpoint_malformed_code(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id="client1",
            response_type="code",
            scope=["openid"],
        )

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "scope": ["openid"],
            "redirect_uri": "http://example.com/authz",
        }

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant[0 : len(access_grant) - 1],
            client_id="client1",
            redirect_uri="http://example.com/authz",
            client_secret="hemlighet",
            grant_type="authorization_code",
        )

        txt = areq.to_urlencoded()

        resp = self.provider.token_endpoint(request=txt)
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert atr["error"] == "unauthorized_client"

    def test_token_endpoint_bad_redirect_uri(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id="client1",
            response_type="code",
            scope=["openid"],
        )

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "scope": ["openid"],
            "redirect_uri": "http://example.com/authz",
        }

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            client_id="client1",
            redirect_uri="http://example.com/authz2",
            client_secret="hemlighet",
            grant_type="authorization_code",
        )

        txt = areq.to_urlencoded()

        resp = self.provider.token_endpoint(request=txt)
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert atr["error"] == "unauthorized_client"

    def test_token_endpoint_ok_state(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id="client1",
            response_type="code",
            scope=["openid"],
        )

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        ae = AuthnEvent("user", "salt")
        _sdb[sid] = {
            "oauth_state": "authz",
            "authn_event": ae.to_json(),
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "state": "state",
            "code_used": False,
            "scope": ["openid"],
            "redirect_uri": "http://example.com/authz",
        }
        _sdb.do_sub(sid, "client_salt")

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            client_id="client1",
            redirect_uri="http://example.com/authz",
            client_secret="hemlighet",
            grant_type="authorization_code",
            state="state",
        )

        txt = areq.to_urlencoded()

        resp = self.provider.token_endpoint(request=txt)
        atr = AccessTokenResponse().deserialize(resp.message, "json")
        assert atr["token_type"] == "Bearer"

    def test_token_endpoint_bad_state(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id="client1",
            response_type="code",
            scope=["openid"],
        )

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "state": "state",
            "code_used": False,
            "scope": ["openid"],
            "redirect_uri": "http://example.com/authz",
        }

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            client_id="client1",
            redirect_uri="http://example.com/authz",
            client_secret="hemlighet",
            grant_type="authorization_code",
            state="other_state",
        )

        txt = areq.to_urlencoded()

        resp = self.provider.token_endpoint(request=txt)
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert atr["error"] == "unauthorized_client"

    def test_token_endpoint_client_credentials(self):
        authreq = AuthorizationRequest(state="state", redirect_uri="http://example.com/authz", client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz",
            "token_endpoint_auth_method": "client_secret_basic",
        }
        areq = CCAccessTokenRequest(grant_type="client_credentials")
        authn = "Basic Y2xpZW50Mjp2ZXJ5c2VjcmV0="
        resp = self.provider.token_endpoint(request=areq.to_urlencoded(), authn=authn)
        parsed = TokenErrorResponse().from_json(resp.message)
        assert parsed["error"] == "unsupported_grant_type"

    def test_token_endpoint_password(self):
        authreq = AuthorizationRequest(state="state", redirect_uri="http://example.com/authz", client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz",
            "token_endpoint_auth_method": "client_secret_basic",
        }
        areq = ROPCAccessTokenRequest(grant_type="password", username="client1", password="password")
        authn = "Basic Y2xpZW50Mjp2ZXJ5c2VjcmV0="
        resp = self.provider.token_endpoint(request=areq.to_urlencoded(), authn=authn)
        parsed = TokenErrorResponse().from_json(resp.message)
        assert parsed["error"] == "unsupported_grant_type"

    def test_token_endpoint_other(self):
        authreq = AuthorizationRequest(state="state", redirect_uri="http://example.com/authz", client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz",
            "token_endpoint_auth_method": "client_secret_basic",
        }
        areq = Message(grant_type="some_other")
        authn = "Basic Y2xpZW50Mjp2ZXJ5c2VjcmV0="
        with pytest.raises(UnSupported):
            self.provider.token_endpoint(request=areq.to_urlencoded(), authn=authn)

    def test_code_grant_type_used(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id="client1",
            response_type="code",
            scope=["openid"],
        )

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "authzreq": "",
            "client_id": "client1",
            "code": access_grant,
            "code_used": True,
            "scope": ["openid"],
            "redirect_uri": "http://example.com/authz",
        }

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            client_id="client1",
            redirect_uri="http://example.com/authz",
            client_secret="hemlighet",
            grant_type="authorization_code",
        )

        txt = areq.to_urlencoded()

        resp = self.provider.token_endpoint(request=txt)
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert atr["error"] == "invalid_grant"

    @pytest.mark.parametrize("response_types", [["token id_token", "id_token"], ["id_token token"]])
    def test_response_types(self, response_types):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id="client1",
            response_type="id_token token",
        )

        self.provider.cdb = {
            "client1": {
                "client_secret": "hemlighet",
                "redirect_uris": [("http://example.com/authz", None)],
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": response_types,
            }
        }

        res = self.provider.auth_init(authreq.to_urlencoded())
        assert isinstance(res, dict) and "areq" in res

    @pytest.mark.parametrize(
        "response_types",
        [
            ["token id_token", "id_token"],
            ["id_token token"],
            ["code id_token"],
            ["id_token code"],
        ],
    )
    def test_response_types_fail(self, response_types):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id="client1",
            response_type="code",
        )

        self.provider.cdb = {
            "client1": {
                "client_secret": "hemlighet",
                "redirect_uris": [("http://example.com/authz", None)],
                "token_endpoint_auth_method": "client_secret_post",
                "response_types": response_types,
            }
        }

        res = self.provider.auth_init(authreq.to_urlencoded())
        assert isinstance(res, Response)

        _res = json.loads(res.message)
        assert _res["error"] == "invalid_request"

    def test_complete_authz_no_cookie(self, session_db_factory):
        provider = Provider(
            "pyoicserver",
            session_db_factory(ISSUER),
            CDB,
            AUTHN_BROKER2,
            AUTHZ,
            verify_client,
            baseurl="https://example.com/as",
        )
        areq = {
            "client_id": "client1",
            "response_type": ["code"],
            "redirect_uri": "http://localhost:8087/authz",
        }
        sid = provider.sdb.access_token.key(user="sub", areq=areq)
        access_code = provider.sdb.access_token(sid=sid)
        provider.sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "client_id": "client1",
            "code": access_code,
            "redirect_uri": "http://localhost:8087/authz",
        }
        response, header, redirect, fragment = provider._complete_authz("sub", areq, sid)
        assert header == []
        assert not fragment
        assert redirect == "http://localhost:8087/authz"
        assert "code" in response

    def test_complete_authz_cookie(self, session_db_factory):
        provider = Provider(
            "pyoicserver",
            session_db_factory(ISSUER),
            CDB,
            AUTHN_BROKER,
            AUTHZ,
            verify_client,
            baseurl="https://example.com/as",
        )
        areq = {
            "client_id": "client1",
            "response_type": ["code"],
            "redirect_uri": "http://localhost:8087/authz",
        }
        sid = provider.sdb.access_token.key(user="sub", areq=areq)
        access_code = provider.sdb.access_token(sid=sid)
        provider.sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "client_id": "client1",
            "code": access_code,
            "redirect_uri": "http://localhost:8087/authz",
        }
        response, header, redirect, fragment = provider._complete_authz("sub", areq, sid)
        assert len(header) == 1
        cookie_header = header[0]
        assert cookie_header[0] == "Set-Cookie"
        assert cookie_header[1].startswith('pyoidc_sso="sub][client1')
        assert not fragment
        assert redirect == "http://localhost:8087/authz"
        assert "code" in response

    def test_complete_authz_other_cookie_exists(self, session_db_factory):
        provider = Provider(
            "pyoicserver",
            session_db_factory(ISSUER),
            CDB,
            AUTHN_BROKER,
            AUTHZ,
            verify_client,
            baseurl="https://example.com/as",
        )
        areq = {
            "client_id": "client1",
            "response_type": ["code"],
            "redirect_uri": "http://localhost:8087/authz",
        }
        sid = provider.sdb.access_token.key(user="sub", areq=areq)
        access_code = provider.sdb.access_token(sid=sid)
        provider.sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "client_id": "client1",
            "code": access_code,
            "redirect_uri": "http://localhost:8087/authz",
        }
        cookie = "Some-cookie=test::test"
        response, header, redirect, fragment = provider._complete_authz("sub", areq, sid, cookie=cookie)
        assert len(header) == 1
        cookie_header = header[0]
        assert cookie_header[1].startswith('pyoidc_sso="sub][client1')
        assert not fragment
        assert redirect == "http://localhost:8087/authz"
        assert "code" in response

    def test_complete_authz_pyoidc_cookie_exists(self, session_db_factory):
        provider = Provider(
            "pyoicserver",
            session_db_factory(ISSUER),
            CDB,
            AUTHN_BROKER,
            AUTHZ,
            verify_client,
            baseurl="https://example.com/as",
        )
        areq = {
            "client_id": "client1",
            "response_type": ["code"],
            "redirect_uri": "http://localhost:8087/authz",
        }
        sid = provider.sdb.access_token.key(user="sub", areq=areq)
        access_code = provider.sdb.access_token(sid=sid)
        provider.sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "client_id": "client1",
            "code": access_code,
            "redirect_uri": "http://localhost:8087/authz",
        }
        cookie = "pyoidc_sso=test::test"
        response, header, redirect, fragment = provider._complete_authz("sub", areq, sid, cookie=cookie)
        assert len(header) == 0
        assert not fragment
        assert redirect == "http://localhost:8087/authz"
        assert "code" in response
