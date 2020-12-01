import datetime
import json
import logging
import os
from http.cookies import SimpleCookie
from time import time
from typing import Any
from typing import Dict
from unittest.mock import Mock
from unittest.mock import patch
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
import responses
from freezegun import freeze_time
from jwkest.jwe import JWEException
from jwkest.jwe import JWEnc
from requests import ConnectionError
from requests.exceptions import MissingSchema
from testfixtures import LogCapture

from oic import rndstr
from oic.exception import FailedAuthentication
from oic.exception import InvalidRequest
from oic.exception import RedirectURIError
from oic.oauth2.message import ErrorResponse
from oic.oic import DEF_SIGN_ALG
from oic.oic import make_openid_request
from oic.oic.consumer import Consumer
from oic.oic.message import AccessTokenRequest
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AuthorizationResponse
from oic.oic.message import CheckSessionRequest
from oic.oic.message import Claims
from oic.oic.message import ClaimsRequest
from oic.oic.message import IdToken
from oic.oic.message import Message
from oic.oic.message import OpenIDSchema
from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import RefreshAccessTokenRequest
from oic.oic.message import RegistrationRequest
from oic.oic.message import RegistrationResponse
from oic.oic.message import TokenErrorResponse
from oic.oic.message import UserInfoRequest
from oic.oic.provider import InvalidRedirectURIError
from oic.oic.provider import InvalidSectorIdentifier
from oic.oic.provider import Provider
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import AuthzHandling
from oic.utils.http_util import CookieDealer
from oic.utils.http_util import Response
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.keyio import ec_init
from oic.utils.keyio import keybundle_from_local_file
from oic.utils.sdb import AuthnEvent
from oic.utils.session_backend import DictSessionBackend
from oic.utils.time_util import epoch_in_a_while
from oic.utils.userinfo import UserInfo

__author__ = "rohe0002"

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "scope": ["openid"],
    "response_type": ["code"],
    "user_info": {"name": None, "email": None, "nickname": None},
    "request_method": "param",
}

SERVER_INFO = {
    "version": "3.0",
    "issuer": "https://connect-op.heroku.com",
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    "flows_supported": ["code", "token", "code token"],
}

CLIENT_CONFIG = {"client_id": "number5", "config": {"issuer": SERVER_INFO["issuer"]}}

CLIENT_CONFIG_2 = {"client_id": "client0", "config": {"issuer": SERVER_INFO["issuer"]}}

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KC_SYM = KeyBundle(
    [
        {"kty": "oct", "key": CLIENT_SECRET, "use": "ver"},
        {"kty": "oct", "key": CLIENT_SECRET, "use": "sig"},
    ]
)
KC_SYM2 = KeyBundle(
    [
        {"kty": "oct", "key": "drickyoughurt", "use": "sig"},
        {"kty": "oct", "key": "drickyoughurt", "use": "ver"},
    ]
)

BASE_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "data/keys"))
KC_RSA = keybundle_from_local_file(
    os.path.join(BASE_PATH, "rsa.key"), "RSA", ["ver", "sig"]
)

KEYJAR = KeyJar()
KEYJAR[CLIENT_ID] = [KC_SYM, KC_RSA]
KEYJAR["number5"] = [KC_SYM2, KC_RSA]
KEYJAR[""] = KC_RSA
KEYJAR["https://connect-op.heroku.com"] = KC_RSA

CDB: Dict[str, Dict[str, Any]] = {
    "number5": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        "redirect_uris": [("http://localhost:8087/authz", None)],
        "post_logout_redirect_uris": [("https://example.com/post_logout", None)],
        "client_salt": "salted",
        "response_types": [
            "code",
            "token",
            "code id_token",
            "none",
            "code token",
            "id_token",
        ],
    },
    "a1b2c3": {
        "redirect_uris": [("http://localhost:8087/authz", None)],
        "client_salt": "salted",
        "client_secret": "very_secret",
        "response_types": ["code", "token", "code id_token"],
    },
    "client0": {
        "redirect_uris": [("http://www.example.org/authz", None)],
        "client_secret": "very_secret",
        "post_logout_redirect_uris": [("https://www.example.org/post_logout", None)],
        "client_salt": "salted",
        "response_types": ["code", "token", "code id_token"],
    },
    CLIENT_ID: {
        "client_secret": CLIENT_SECRET,
        "redirect_uris": [("http://localhost:8087/authz", None)],
        "client_salt": "salted",
        "token_endpoint_auth_method": "client_secret_post",
        "response_types": ["code", "token", "code id_token"],
    },
}

USERDB = {
    "user": {
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
        "sub": "user",
    },
    "username": {
        "name": "Linda Lindgren",
        "nickname": "Linda",
        "email": "linda@example.com",
        "verified": True,
        "sub": "username",
        "extra_claim": "extra_claim_value",
    },
}

URLMAP = {CLIENT_ID: ["https://example.com/authz"]}


def _eq(l1, l2):
    return set(l1) == set(l2)


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        if cookie == "FAIL":
            return None, 0
        else:
            return {"uid": self.user}, time()


AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))

# dealing with authorization
AUTHZ = AuthzHandling()
SYMKEY = rndstr(16)  # symmetric key used to encrypt cookie info
USERINFO = UserInfo(USERDB)


class TestProvider(object):
    @pytest.fixture(autouse=True)
    def create_provider(self, session_db_factory):
        self.provider = Provider(
            SERVER_INFO["issuer"],
            session_db_factory(SERVER_INFO["issuer"]),
            CDB,
            AUTHN_BROKER,
            USERINFO,
            AUTHZ,
            verify_client,
            SYMKEY,
            urlmap=URLMAP,
            keyjar=KEYJAR,
        )
        self.provider.baseurl = self.provider.name

        self.cons = Consumer(
            DictSessionBackend(),
            CONSUMER_CONFIG.copy(),
            CLIENT_CONFIG,
            server_info=SERVER_INFO,
        )
        self.cons.behaviour = {
            "request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]
        }
        self.cons.keyjar[""] = KC_RSA
        self.cons.keyjar.import_jwks(
            self.provider.keyjar.export_jwks(), self.cons.issuer
        )
        self.cons.provider_info = ProviderConfigurationResponse(
            issuer=SERVER_INFO["issuer"]
        )

        self.cons2 = Consumer(
            {}, CONSUMER_CONFIG.copy(), CLIENT_CONFIG_2, server_info=SERVER_INFO
        )
        self.cons2.behaviour = {
            "request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]
        }
        self.cons2.keyjar[""] = KC_RSA

    def test_authorization_endpoint(self):
        bib = {
            "scope": ["openid"],
            "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
            "redirect_uri": "http://localhost:8087/authz",
            "response_type": ["code"],
            "client_id": "a1b2c3",
            "nonce": "Nonce",
        }

        arq = AuthorizationRequest(**bib)

        resp = self.provider.authorization_endpoint(request=arq.to_urlencoded())
        parsed = parse_qs(urlparse(resp.message).query)
        assert parsed["scope"] == ["openid"]
        assert parsed["state"][0] == "id-6da9ca0cc23959f5f33e8becd9b08cae"
        assert "code" in parsed

    def test_provider_features_extra_claims(self):
        self.provider.extra_claims = ["claim_1", "claim_2"]
        features = self.provider.provider_features()
        assert "claim_1" in features["claims_supported"]
        assert "claim_2" in features["claims_supported"]

    def test_provider_features_extra_scopes(self):
        self.provider.extra_scope_dict = {"my_scope": ["claim_1", "claim_2"]}
        features = self.provider.provider_features()
        assert "my_scope" in features["scopes_supported"]
        assert "claim_1" in features["claims_supported"]
        assert "claim_2" in features["claims_supported"]

    def test_authorization_endpoint_request(self):
        bib = {
            "scope": ["openid"],
            "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
            "redirect_uri": "http://localhost:8087/authz",
            "response_type": ["code", "id_token"],
            "client_id": "a1b2c3",
            "nonce": "Nonce",
            "prompt": ["none"],
        }

        req = AuthorizationRequest(**bib)
        # want to be someone else !
        ic = {"sub": {"value": "userX"}}
        _keys = self.provider.keyjar.get_signing_key(key_type="RSA")
        req["request"] = make_openid_request(
            req, _keys, idtoken_claims=ic, request_object_signing_alg="RS256"
        )

        with pytest.raises(FailedAuthentication):
            self.provider.authorization_endpoint(request=req.to_urlencoded())

    def test_authorization_endpoint_id_token(self):
        bib = {
            "scope": ["openid"],
            "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
            "redirect_uri": "http://localhost:8087/authz",
            "response_type": ["code", "id_token"],
            "client_id": "a1b2c3",
            "nonce": "Nonce",
            "prompt": ["none"],
        }

        req = AuthorizationRequest(**bib)
        areq = AuthorizationRequest(
            response_type="code",
            client_id="client_1",
            redirect_uri="http://example.com/authz",
            scope=["openid"],
            state="state000",
        )

        sdb = self.provider.sdb
        ae = AuthnEvent("userX", "salt")
        sid = sdb.create_authz_session(ae, areq)
        sdb.do_sub(sid, "client_salt")
        _info = sdb[sid]
        # All this is jut removed when the id_token is constructed
        # The proper information comes from the session information
        _user_info = IdToken(
            iss="https://foo.example.om",
            sub="foo",
            aud=bib["client_id"],
            exp=epoch_in_a_while(minutes=10),
            acr="2",
            nonce=bib["nonce"],
        )

        idt = self.provider.id_token_as_signed_jwt(
            _info, access_token="access_token", user_info=_user_info
        )

        req["id_token"] = idt
        query_string = req.to_urlencoded()

        # client_id not in id_token["aud"] so login required
        resp = self.provider.authorization_endpoint(request=query_string, cookie="FAIL")
        parsed_resp = parse_qs(urlparse(resp.message).fragment)
        assert parsed_resp["error"][0] == "login_required"

        req["client_id"] = "client_1"
        query_string = req.to_urlencoded()

        # client_id is in id_token["aud"] so no login required
        resp = self.provider.authorization_endpoint(request=query_string, cookie="FAIL")

        assert resp.message.startswith("http://localhost:8087/authz")

    def test_authorization_endpoint_bad_scope(self):
        bib = {
            "scope": ["openid", "offline_access"],
            "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
            "redirect_uri": "http://localhost:8087/authz",
            "response_type": ["code"],
            "client_id": "a1b2c3",
        }

        arq = AuthorizationRequest(**bib)
        resp = self.provider.authorization_endpoint(request=arq.to_urlencoded())
        assert resp.status_code == 303
        parsed = parse_qs(urlparse(resp.message).query)
        assert parsed["error"][0] == "invalid_request"
        assert parsed["error_description"][0] == "consent in prompt"

    def test_authenticated(self):
        _state, location = self.cons.begin(
            "openid", "code", path="http://localhost:8087"
        )

        resp = self.provider.authorization_endpoint(request=urlparse(location).query)

        parsed = urlparse(resp.message)
        assert (
            "{}://{}{}".format(parsed.scheme, parsed.netloc, parsed.path)
            == "http://localhost:8087/authz"
        )

        part = self.cons.parse_authz(query=resp.message)

        assert isinstance(part, tuple)
        aresp = part[0]
        assert part[1] is None
        assert part[2] is None

        assert isinstance(aresp, AuthorizationResponse)
        assert _eq(aresp.keys(), ["code", "state", "scope", "client_id", "iss"])

        assert _eq(
            self.cons.grant[_state].keys(),
            ["code", "tokens", "id_token", "exp_in", "seed", "grant_expiration_time"],
        )

    def test_authenticated_url(self):
        state, location = self.cons.begin(
            "openid", "code", path="http://localhost:8087"
        )

        resp = self.provider.authorization_endpoint(request=urlparse(location).query)

        aresp = self.cons.parse_response(
            AuthorizationResponse, resp.message, sformat="urlencoded"
        )

        assert isinstance(aresp, AuthorizationResponse)
        assert _eq(aresp.keys(), ["code", "state", "scope", "client_id", "iss"])

    def test_authenticated_hybrid(self):
        _state, location = self.cons.begin(
            scope="openid email claims_in_id_token",
            response_type="code id_token",
            path="http://localhost:8087",
        )

        resp = self.provider.authorization_endpoint(request=urlparse(location).query)

        part = self.cons.parse_authz(resp.message)

        assert isinstance(part, tuple)
        aresp = part[0]
        assert part[1] is None
        id_token = part[2]

        assert isinstance(aresp, AuthorizationResponse)
        assert _eq(aresp.keys(), ["scope", "state", "id_token", "client_id", "code"])

        assert _eq(
            self.cons.grant[_state].keys(),
            ["code", "id_token", "tokens", "exp_in", "grant_expiration_time", "seed"],
        )
        assert isinstance(id_token, IdToken)
        assert _eq(
            id_token.keys(),
            ["nonce", "c_hash", "sub", "iss", "acr", "exp", "auth_time", "iat", "aud"],
        )

    def test_authenticated_token(self):
        _state, location = self.cons.begin(
            "openid", response_type="token", path="http://localhost:8087"
        )

        resp = self.provider.authorization_endpoint(request=urlparse(location).query)
        parsed = parse_qs(urlparse(resp.message).fragment)
        assert parsed["token_type"][0] == "Bearer"
        assert "access_token" in parsed

    def test_authenticated_none(self):
        _state, location = self.cons.begin(
            "openid", response_type="none", path="http://localhost:8087"
        )

        resp = self.provider.authorization_endpoint(request=location.split("?")[1])
        parsed = urlparse(resp.message)
        assert (
            "{}://{}{}".format(parsed.scheme, parsed.netloc, parsed.path)
            == "http://localhost:8087/authz"
        )
        assert "state" in parse_qs(parsed.query)

    def test_code_grant_type_ok(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id=CLIENT_ID,
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
            "authzreq": authreq.to_json(),
            "client_id": CLIENT_ID,
            "code": access_grant,
            "code_used": False,
            "scope": ["openid"],
            "redirect_uri": "http://example.com/authz",
        }
        _sdb.do_sub(sid, "client_salt")

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            client_id=CLIENT_ID,
            redirect_uri="http://example.com/authz",
            client_secret=CLIENT_SECRET,
            grant_type="authorization_code",
        )
        resp = self.provider.code_grant_type(areq)
        atr = AccessTokenResponse().deserialize(resp.message, "json")
        assert _eq(atr.keys(), ["token_type", "id_token", "access_token", "scope"])

    def test_code_grant_type_missing_code(self):
        # Construct Access token request
        areq = AccessTokenRequest(
            client_id=CLIENT_ID,
            redirect_uri="http://example.com/authz",
            client_secret=CLIENT_SECRET,
            grant_type="authorization_code",
        )
        resp = self.provider.code_grant_type(areq)
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert atr["error"] == "invalid_request"
        assert atr["error_description"] == "Missing code"

    def test_code_grant_type_revoked(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id=CLIENT_ID,
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
            "authzreq": authreq.to_json(),
            "client_id": CLIENT_ID,
            "code": access_grant,
            "revoked": True,
            "scope": ["openid"],
            "redirect_uri": "http://example.com/authz",
        }
        _sdb.do_sub(sid, "client_salt")

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            client_id=CLIENT_ID,
            redirect_uri="http://example.com/authz",
            client_secret=CLIENT_SECRET,
            grant_type="authorization_code",
        )
        resp = self.provider.code_grant_type(areq)
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert atr["error"] == "invalid_request"
        assert atr["error_description"] == "Token is revoked"

    def test_code_grant_type_no_session(self):
        # Construct Access token request
        areq = AccessTokenRequest(
            code="some grant",
            client_id=CLIENT_ID,
            redirect_uri="http://example.com/authz",
            client_secret=CLIENT_SECRET,
            grant_type="authorization_code",
        )
        resp = self.provider.code_grant_type(areq)
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert atr["error"] == "invalid_request"
        assert atr["error_description"] == "Code is invalid"

    def test_code_grant_type_missing_redirect_uri(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id=CLIENT_ID,
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
            "authzreq": authreq.to_json(),
            "client_id": CLIENT_ID,
            "code": access_grant,
            "code_used": False,
            "scope": ["openid"],
            "redirect_uri": "http://example.com/authz",
        }
        _sdb.do_sub(sid, "client_salt")

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            grant_type="authorization_code",
        )
        resp = self.provider.code_grant_type(areq)
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert atr["error"] == "invalid_request"
        assert atr["error_description"] == "Missing redirect_uri"

    def test_code_grant_type_used(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id=CLIENT_ID,
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
            "authzreq": authreq.to_json(),
            "client_id": CLIENT_ID,
            "code": access_grant,
            "code_used": True,
            "scope": ["openid"],
            "redirect_uri": "http://example.com/authz",
        }
        _sdb.do_sub(sid, "client_salt")

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            client_id=CLIENT_ID,
            redirect_uri="http://example.com/authz",
            client_secret=CLIENT_SECRET,
            grant_type="authorization_code",
        )
        resp = self.provider.code_grant_type(areq)
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert atr["error"] == "access_denied"
        assert atr["error_description"] == "Access Code already used"

    def test_code_grant_type_refresh(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id=CLIENT_ID,
            response_type="code",
            scope=["openid offline_access"],
            prompt="consent",
        )

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        ae = AuthnEvent("user", "salt")
        _sdb[sid] = {
            "oauth_state": "authz",
            "authn_event": ae.to_json(),
            "authzreq": authreq.to_json(),
            "client_id": CLIENT_ID,
            "code": access_grant,
            "code_used": False,
            "scope": ["openid", "offline_access"],
            "redirect_uri": "http://example.com/authz",
        }
        _sdb.do_sub(sid, "client_salt")

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            client_id=CLIENT_ID,
            redirect_uri="http://example.com/authz",
            client_secret=CLIENT_SECRET,
            grant_type="authorization_code",
        )
        resp = self.provider.code_grant_type(areq)
        atr = AccessTokenResponse().deserialize(resp.message, "json")
        assert _eq(
            atr.keys(),
            ["token_type", "id_token", "access_token", "scope", "refresh_token"],
        )

    def test_code_grant_type_id_token_claims(self):
        id_token_claims = Claims(name={"essential": True})
        claims_req = ClaimsRequest(id_token=id_token_claims)
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id=CLIENT_ID,
            response_type="code",
            scope=["openid"],
            claims=claims_req,
        )

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        ae = AuthnEvent("user", "salt")
        _sdb[sid] = {
            "oauth_state": "authz",
            "authn_event": ae.to_json(),
            "authzreq": authreq.to_json(),
            "client_id": CLIENT_ID,
            "code": access_grant,
            "code_used": False,
            "scope": ["openid"],
            "redirect_uri": "http://example.com/authz",
        }
        _sdb.do_sub(sid, "client_salt")

        # Construct Access token request
        areq = AccessTokenRequest(
            code=access_grant,
            client_id=CLIENT_ID,
            redirect_uri="http://example.com/authz",
            client_secret=CLIENT_SECRET,
            grant_type="authorization_code",
        )
        resp = self.provider.code_grant_type(areq)
        atr = AccessTokenResponse().deserialize(resp.message, "json")
        assert _eq(atr.keys(), ["token_type", "id_token", "access_token", "scope"])
        assert atr.verify(keyjar=KEYJAR)
        assert "name" in atr["id_token"]

    def test_client_credentials_grant_type(self):
        resp = self.provider.client_credentials_grant_type(Message())
        parsed = ErrorResponse().from_json(resp.message)
        assert parsed["error"] == "unsupported_grant_type"
        assert parsed["error_description"] == "Unsupported grant_type"

    def test_password_grant_type(self):
        resp = self.provider.password_grant_type(Message())
        parsed = ErrorResponse().from_json(resp.message)
        assert parsed["error"] == "unsupported_grant_type"
        assert parsed["error_description"] == "Unsupported grant_type"

    def test_authz_endpoint(self):
        _state, location = self.cons.begin(
            "openid", response_type=["code", "token"], path="http://localhost:8087"
        )
        resp = self.provider.authorization_endpoint(request=urlparse(location).query)

        parsed = parse_qs(urlparse(resp.message).fragment)
        assert parsed["token_type"][0] == "Bearer"
        assert "code" in parsed

    def test_idtoken(self):
        AREQ = AuthorizationRequest(
            response_type="code",
            client_id=CLIENT_ID,
            redirect_uri="http://example.com/authz",
            scope=["openid"],
            state="state000",
        )

        ae = AuthnEvent("sub", "salt")
        sid = self.provider.sdb.create_authz_session(ae, AREQ)
        self.provider.sdb.do_sub(sid, "client_salt")
        session = self.provider.sdb[sid]

        id_token = self.provider.id_token_as_signed_jwt(session)
        assert len(id_token.split(".")) == 3

    def test_idtoken_with_extra_claims(self):
        areq = AuthorizationRequest(
            response_type="code",
            client_id=CLIENT_ID,
            redirect_uri="http://example.com/authz",
            scope=["openid"],
            state="state000",
        )
        aevent = AuthnEvent("sub", "salt")
        sid = self.provider.sdb.create_authz_session(aevent, areq)
        self.provider.sdb.do_sub(sid, "client_salt")
        session = self.provider.sdb[sid]

        claims = {"k1": "v1", "k2": 32}

        id_token = self.provider.id_token_as_signed_jwt(session, extra_claims=claims)
        parsed = IdToken().from_jwt(id_token, keyjar=self.provider.keyjar)

        for key, value in claims.items():
            assert parsed[key] == value

    def test_userinfo_endpoint(self):
        self.cons.client_secret = "drickyoughurt"
        self.cons.config["response_type"] = ["token"]
        self.cons.config["request_method"] = "parameter"
        state, location = self.cons.begin(
            "openid", "token", path="http://localhost:8087"
        )

        resp = self.provider.authorization_endpoint(request=urlparse(location).query)

        # redirect
        atr = AuthorizationResponse().deserialize(
            urlparse(resp.message).fragment, "urlencoded"
        )

        uir = UserInfoRequest(access_token=atr["access_token"], schema="openid")

        resp = self.provider.userinfo_endpoint(request=uir.to_urlencoded())
        ident = OpenIDSchema().deserialize(resp.message, "json")
        assert _eq(ident.keys(), ["nickname", "sub", "name", "email"])

    def test_userinfo_endpoint_expired(self):
        self.cons.client_secret = "drickyoughurt"
        self.cons.config["response_type"] = ["token"]
        self.cons.config["request_method"] = "parameter"
        state, location = self.cons.begin(
            "openid", "token", path="http://localhost:8087"
        )

        initial_datetime = datetime.datetime(2018, 2, 5, 10, 0, 0, 0)
        final_datetime = datetime.datetime(2018, 2, 9, 10, 0, 0, 0)
        with freeze_time(initial_datetime) as frozen:
            resp = self.provider.authorization_endpoint(
                request=urlparse(location).query
            )

            # redirect
            atr = AuthorizationResponse().deserialize(
                urlparse(resp.message).fragment, "urlencoded"
            )
            frozen.move_to(final_datetime)

            uir = UserInfoRequest(access_token=atr["access_token"], schema="openid")
            resp = self.provider.userinfo_endpoint(request=uir.to_urlencoded())

        message = json.loads(resp.message)
        assert message["error"] == "invalid_token"
        assert message["error_description"] == "Token is expired"

    def test_userinfo_endpoint_extra_claim(self):
        # We have to recreate the cache again
        self.provider.extra_claims = ["extra_claim"]
        self.provider.capabilities = self.provider.provider_features()

        self.cons.client_secret = "drickyoughurt"
        self.cons.config["response_type"] = ["token"]
        self.cons.config["request_method"] = "parameter"
        # Request the extra claim
        self.cons.consumer_config["user_info"] = {"extra_claim": None}
        state, location = self.cons.begin(
            "openid", "token", path="http://localhost:8087"
        )

        resp = self.provider.authorization_endpoint(request=urlparse(location).query)

        # redirect
        atr = AuthorizationResponse().deserialize(
            urlparse(resp.message).fragment, "urlencoded"
        )

        uir = UserInfoRequest(access_token=atr["access_token"], schema="openid")

        resp = self.provider.userinfo_endpoint(request=uir.to_urlencoded())
        ident = OpenIDSchema().deserialize(resp.message, "json")
        assert _eq(ident.keys(), ["sub", "extra_claim"])

    def test_userinfo_endpoint_unknown_claim(self):
        self.cons.client_secret = "drickyoughurt"
        self.cons.config["response_type"] = ["token"]
        self.cons.config["request_method"] = "parameter"
        # Request the extra claim
        self.cons.consumer_config["user_info"] = {"extra_claim": None}
        state, location = self.cons.begin(
            "openid", "token", path="http://localhost:8087"
        )

        resp = self.provider.authorization_endpoint(request=urlparse(location).query)

        # redirect
        atr = AuthorizationResponse().deserialize(
            urlparse(resp.message).fragment, "urlencoded"
        )

        uir = UserInfoRequest(access_token=atr["access_token"], schema="openid")

        resp = self.provider.userinfo_endpoint(request=uir.to_urlencoded())
        ident = OpenIDSchema().deserialize(resp.message, "json")
        assert _eq(ident.keys(), ["sub"])

    def test_userinfo_endpoint_extra_scopes(self):
        # We have to recreate the cache again
        self.provider.extra_scope_dict = {"extra_scope": ["extra_claim"]}
        self.provider.capabilities = self.provider.provider_features()

        self.cons.client_secret = "drickyoughurt"
        self.cons.consumer_config["user_info"] = {"extra_claim": None}
        self.cons.config["response_type"] = ["token"]
        self.cons.config["request_method"] = "parameter"
        # Request the extra scope
        state, location = self.cons.begin(
            "openid extra_scope", "token", path="http://localhost:8087"
        )

        resp = self.provider.authorization_endpoint(request=urlparse(location).query)

        # redirect
        atr = AuthorizationResponse().deserialize(
            urlparse(resp.message).fragment, "urlencoded"
        )

        uir = UserInfoRequest(access_token=atr["access_token"], schema="openid")

        resp = self.provider.userinfo_endpoint(request=uir.to_urlencoded())
        ident = OpenIDSchema().deserialize(resp.message, "json")
        assert _eq(ident.keys(), ["sub", "extra_claim"])

    def test_userinfo_endpoint_authn(self):
        self.cons.client_secret = "drickyoughurt"
        self.cons.config["response_type"] = ["token"]
        self.cons.config["request_method"] = "parameter"
        state, location = self.cons.begin(
            "openid", "token", path="http://localhost:8087"
        )

        resp = self.provider.authorization_endpoint(request=urlparse(location).query)

        # redirect
        atr = AuthorizationResponse().deserialize(
            urlparse(resp.message).fragment, "urlencoded"
        )

        uir = UserInfoRequest(schema="openid")

        resp = self.provider.userinfo_endpoint(
            request=uir.to_urlencoded(), authn="Bearer " + atr["access_token"]
        )
        ident = OpenIDSchema().deserialize(resp.message, "json")
        assert _eq(ident.keys(), ["nickname", "sub", "name", "email"])

    def test_userinfo_endpoint_missing_client(self):
        self.provider.cdb["unknownclient"] = {
            "client_secret": "unknownclient",
            "redirect_uris": [("http://localhost:8087/authz", None)],
            "post_logout_redirect_uris": [("https://example.com/post_logout", None)],
            "client_salt": "salted",
            "response_types": [
                "code",
                "token",
                "code id_token",
                "none",
                "code token",
                "id_token",
            ],
        }
        self.cons.client_id = "unknownclient"
        self.cons.client_secret = "unknownclient"
        self.cons.config["response_type"] = ["token"]
        self.cons.config["request_method"] = "parameter"
        state, location = self.cons.begin(
            "openid", "token", path="http://localhost:8087"
        )

        resp = self.provider.authorization_endpoint(request=urlparse(location).query)

        # redirect
        atr = AuthorizationResponse().deserialize(
            urlparse(resp.message).fragment, "urlencoded"
        )

        uir = UserInfoRequest(schema="openid")

        del self.provider.cdb["unknownclient"]
        resp = self.provider.userinfo_endpoint(
            request=uir.to_urlencoded(), authn="Bearer " + atr["access_token"]
        )
        ident = OpenIDSchema().deserialize(resp.message, "json")
        assert ident["error"] == "unauthorized_client"

    def test_userinfo_endpoint_malformed(self):
        uir = UserInfoRequest(schema="openid")

        resp = self.provider.userinfo_endpoint(
            request=uir.to_urlencoded(), authn="Not a token"
        )

        assert json.loads(resp.message) == {
            "error_description": "Token is malformed",
            "error": "invalid_request",
        }

    def test_userinfo_endpoint_mising_authn(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id=CLIENT_ID,
            response_type="code",
            scope=["openid", "offline_access"],
            prompt="consent",
        )
        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        # authn_event is missing - this can happen for offline requests
        _sdb[sid] = {
            "sub": "my_sub",
            "oauth_state": "authz",
            "uid": "user",
            "authzreq": authreq.to_json(),
            "client_id": CLIENT_ID,
            "code": access_grant,
            "code_used": False,
            "scope": ["openid", "offline_access"],
            "redirect_uri": "http://example.com/authz",
        }

        uir = UserInfoRequest(access_token=access_grant, schema="openid")

        resp = self.provider.userinfo_endpoint(request=uir.to_urlencoded())
        ident = OpenIDSchema().deserialize(resp.message, "json")
        assert _eq(ident.keys(), ["sub"])

    def test_check_session_endpoint(self):
        session = {"sub": "UserID", "client_id": "number5"}
        idtoken = self.provider.id_token_as_signed_jwt(session)
        csr = CheckSessionRequest(id_token=idtoken)

        info = self.provider.check_session_endpoint(request=csr.to_urlencoded())
        idt = IdToken().deserialize(info.message, "json")
        assert _eq(idt.keys(), ["sub", "aud", "iss", "acr", "exp", "iat"])
        assert idt["iss"] == self.provider.name

    def test_response_mode_fragment(self):
        areq = {"response_mode": "fragment"}
        assert self.provider.response_mode(areq, True) is None
        with pytest.raises(InvalidRequest):
            self.provider.response_mode(areq, False)

    def test_response_mode_query(self):
        areq = {"response_mode": "query"}
        assert self.provider.response_mode(areq, False) is None
        with pytest.raises(InvalidRequest):
            self.provider.response_mode(areq, True)

    def test_response_mode_form_post(self):
        areq = {"response_mode": "form_post"}
        aresp = AuthorizationResponse()
        aresp["state"] = "state"
        response = self.provider.response_mode(
            areq, False, redirect_uri="http://example.com", aresp=aresp, headers=""
        )
        assert "Submit This Form" in response.message
        assert "http://example.com" in response.message
        assert '<input type="hidden" name="state" value="state"/>' in response.message

    def test_auth_init_invalid(self):
        areq = {
            "response_mode": "unknown",
            "redirect_uri": "http://localhost:8087/authz",
            "client_id": "number5",
            "scope": "openid",
            "response_type": "code",
            "client_secret": "drickyoghurt",
        }
        response = self.provider.auth_init(areq)

        assert isinstance(response, Response)
        assert response.status_code == 400
        assert json.loads(response.message) == {
            "error": "invalid_request",
            "error_description": "Contains unsupported response mode",
        }

    @patch("oic.oic.provider.utc_time_sans_frac", Mock(return_value=123456))
    def test_client_secret_expiration_time(self):
        exp_time = self.provider.client_secret_expiration_time()
        assert exp_time == 209856

    def test_registration_endpoint_post(self):
        req = RegistrationRequest()

        req["application_type"] = "web"
        req["client_name"] = "My super service"
        req["redirect_uris"] = ["http://example.com/authz"]
        req["contacts"] = ["foo@example.com"]
        req["response_types"] = ["code"]

        resp = self.provider.registration_endpoint(request=req.to_json())

        regresp = RegistrationResponse().deserialize(resp.message, "json")
        assert _eq(
            regresp.keys(),
            [
                "redirect_uris",
                "contacts",
                "application_type",
                "client_name",
                "registration_client_uri",
                "client_secret_expires_at",
                "registration_access_token",
                "client_id",
                "client_secret",
                "client_id_issued_at",
                "response_types",
            ],
        )

    def test_registration_endpoint_post_unicode(self):
        data = (
            "application_type=web&client_name=M%C3%A1+supe%C5%99+service&"
            "redirect_uris=http%3A%2F%2Fexample.com%2Fauthz&response_types=code"
        )
        resp = self.provider.registration_endpoint(request=data)

        regresp = RegistrationResponse().deserialize(resp.message, "json")
        assert _eq(
            regresp.keys(),
            [
                "redirect_uris",
                "application_type",
                "client_name",
                "registration_client_uri",
                "client_secret_expires_at",
                "registration_access_token",
                "client_id",
                "client_secret",
                "client_id_issued_at",
                "response_types",
            ],
        )

    def test_registration_endpoint_get(self):
        rr = RegistrationRequest(
            operation="register",
            redirect_uris=["http://example.org/new"],
            response_types=["code"],
        )
        registration_req = rr.to_json()
        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)

        authn = " ".join(["Bearer", regresp["registration_access_token"]])
        query = "=".join(["client_id", regresp["client_id"]])
        resp = self.provider.registration_endpoint(
            request=query, authn=authn, method="GET"
        )

        assert json.loads(resp.message) == regresp.to_dict()

    def test_registration_endpoint_delete(self):
        resp = self.provider.registration_endpoint(request="", method="PUT")
        assert json.loads(resp.message) == {
            "error": "Unsupported operation",
            "error_description": "Altering of the registration is not supported",
        }

    def test_registration_endpoint_put(self):
        resp = self.provider.registration_endpoint(request="", method="DELETE")
        assert json.loads(resp.message) == {
            "error": "Unsupported operation",
            "error_description": "Deletion of the registration is not supported",
        }

    def test_registration_endpoint_unsupported(self):
        resp = self.provider.registration_endpoint(request="", method="HEAD")
        assert json.loads(resp.message) == {
            "error": "Unsupported method",
            "error_description": "Unsupported HTTP method",
        }

    def test_do_client_registration_invalid_sector_uri(self):
        rr = RegistrationRequest(
            operation="register",
            sector_identifier_uri="https://example.com",
            redirect_uris=["http://example.com/changed"],
        )
        redirects = ["http://example.com/present"]
        with responses.RequestsMock() as rsps:
            rsps.add(rsps.GET, "https://example.com", body=json.dumps(redirects))
            resp = self.provider.do_client_registration(rr, "client0")

        assert resp.status_code == 400
        error = json.loads(resp.message)
        assert error["error"] == "invalid_configuration_parameter"

    def test_registration_endpoint_with_non_https_redirect_uri_implicit_flow(self):
        params = {
            "application_type": "web",
            "redirect_uris": ["http://example.com/authz"],
            "response_types": ["id_token", "token"],
        }
        req = RegistrationRequest(**params)
        resp = self.provider.registration_endpoint(request=req.to_json())

        assert resp.status_code == 400
        error = json.loads(resp.message)
        assert error["error"] == "invalid_redirect_uri"

    def test_verify_redirect_uris_with_https_code_flow(self):
        params = {
            "application_type": "web",
            "redirect_uris": ["http://example.com/authz"],
            "response_types": ["code"],
        }
        request = RegistrationRequest(**params)
        verified_uris = self.provider.verify_redirect_uris(request)
        assert verified_uris == [("http://example.com/authz", None)]

    def test_verify_redirect_uris_with_non_https_redirect_uri_implicit_flow(self):
        params = {
            "application_type": "web",
            "redirect_uris": ["http://example.com/authz"],
            "response_types": ["id_token", "token"],
        }
        request = RegistrationRequest(**params)

        with pytest.raises(InvalidRedirectURIError) as exc_info:
            self.provider.verify_redirect_uris(request)

        assert str(exc_info.value) == "None https redirect_uri not allowed"

    def test_verify_redirect_uris_unicode(self):
        url = "http://example.com/a\xc5\xaf\xc5\xa5h\xc5\xbe"
        params = {
            "application_type": "web",
            "redirect_uris": [url],
            "response_types": ["code"],
        }
        request = RegistrationRequest(**params)
        verified_uris = self.provider.verify_redirect_uris(request)
        assert verified_uris == [(url, None)]

    def test_provider_key_setup(self, tmpdir, session_db_factory):
        path = tmpdir.strpath

        # Path is actually just a random name we turn into a subpath of
        # our current directory, that doesn't work with drive letters on
        # windows, so we throw them away and add a '.' for a local path.
        path = "." + os.path.splitdrive(path)[1].replace(os.path.sep, "/")

        provider = Provider(
            "pyoicserv",
            session_db_factory(SERVER_INFO["issuer"]),
            {},
            None,
            None,
            None,
            None,
            None,
        )
        provider.baseurl = "http://www.example.com"
        provider.key_setup(path, path, sig={"format": "jwk", "alg": "RSA"})

        keys = provider.keyjar.get_signing_key("RSA")

        assert len(keys) == 1
        assert provider.jwks_uri == "http://www.example.com/{}/jwks".format(path)

    @pytest.mark.parametrize(
        "uri",
        [
            "http://example.org/foo",
            "http://example.com/cb",
            "http://example.org/cb?got=you",
            "http://example.org/cb/foo?got=you",
        ],
    )
    def test_verify_redirect_uri_faulty_without_query(self, uri):
        rr = RegistrationRequest(
            operation="register",
            redirect_uris=["http://example.org/cb"],
            response_types=["code"],
        )
        registration_req = rr.to_json()

        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)
        cid = regresp["client_id"]

        areq = AuthorizationRequest(
            redirect_uri=uri, client_id=cid, response_type="code", scope="openid"
        )

        with pytest.raises(RedirectURIError):
            self.provider._verify_redirect_uri(areq)

    @pytest.mark.parametrize(
        "uri",
        [
            "http://example.org/foo",
            "http://example.com/cb",
            "http://example.org/cb?got=you",
            "http://example.org/cb?test=fail",
            "http://example.org/cb/foo?got=you",
        ],
    )
    def test_verify_redirect_uri_faulty_with_query(self, uri):
        rr = RegistrationRequest(
            operation="register",
            redirect_uris=["http://example.org/cb?test=test"],
            response_types=["code"],
        )
        registration_req = rr.to_json()

        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)
        cid = regresp["client_id"]

        areq = AuthorizationRequest(
            redirect_uri=uri, client_id=cid, response_type="code", scope="openid"
        )

        with pytest.raises(RedirectURIError):
            self.provider._verify_redirect_uri(areq)

    @pytest.mark.parametrize("uri", ["http://example.org/cb"])
    def test_verify_redirect_uri_correct_without_query(self, uri):
        rr = RegistrationRequest(
            operation="register",
            redirect_uris=["http://example.org/cb"],
            response_types=["code"],
        )
        registration_req = rr.to_json()
        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)
        cid = regresp["client_id"]

        areq = AuthorizationRequest(
            redirect_uri=uri, client_id=cid, response_type="code", scope="openid"
        )

        self.provider._verify_redirect_uri(areq)

    @pytest.mark.parametrize(
        "uri", ["http://example.org/cb", "http://example.org/cb?test=test"]
    )
    def test_verify_redirect_uri_correct_with_query(self, uri):
        rr = RegistrationRequest(
            operation="register",
            redirect_uris=["http://example.org/cb", "http://example.org/cb?test=test"],
            response_types=["code"],
        )
        registration_req = rr.to_json()
        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)
        cid = regresp["client_id"]

        areq = AuthorizationRequest(
            redirect_uri=uri, client_id=cid, response_type="code", scope="openid"
        )

        self.provider._verify_redirect_uri(areq)

    def test_verify_sector_identifier_no_scheme(self):
        rr = RegistrationRequest(
            operation="register", sector_identifier_uri="example.com"
        )
        with LogCapture(level=logging.DEBUG) as logcap:
            message = "Couldn't open sector_identifier_uri"
            with pytest.raises(InvalidSectorIdentifier, match=message):
                self.provider._verify_sector_identifier(rr)

        assert len(logcap.records) == 2
        # First log record is from server...
        assert isinstance(logcap.records[1].msg, MissingSchema)
        error = (
            "Invalid URL 'example.com': No schema supplied. Perhaps you meant "
            "http://example.com?"
        )
        assert str(logcap.records[1].msg) == error

    def test_verify_sector_identifier_nonreachable(self):
        rr = RegistrationRequest(
            operation="register", sector_identifier_uri="https://example.com"
        )
        with responses.RequestsMock() as rsps, LogCapture(
            level=logging.DEBUG
        ) as logcap:
            rsps.add(rsps.GET, "https://example.com", status=404)
            message = "Couldn't open sector_identifier_uri"
            with pytest.raises(InvalidSectorIdentifier, match=message):
                self.provider._verify_sector_identifier(rr)

        assert len(logcap.records) == 0

    def test_verify_sector_identifier_error(self):
        rr = RegistrationRequest(
            operation="register", sector_identifier_uri="https://example.com"
        )
        error = ConnectionError("broken connection")
        with responses.RequestsMock() as rsps, LogCapture(
            level=logging.DEBUG
        ) as logcap:
            rsps.add(rsps.GET, "https://example.com", body=error)
            with pytest.raises(
                InvalidSectorIdentifier, match="Couldn't open sector_identifier_uri"
            ):
                self.provider._verify_sector_identifier(rr)

        assert len(logcap.records) == 2
        # First log record is from server...
        assert logcap.records[1].msg == error

    def test_verify_sector_identifier_malformed(self):
        rr = RegistrationRequest(
            operation="register", sector_identifier_uri="https://example.com"
        )
        body = "This is not the JSON you are looking for"
        with responses.RequestsMock() as rsps, LogCapture(
            level=logging.DEBUG
        ) as logcap:
            rsps.add(rsps.GET, "https://example.com", body=body)
            with pytest.raises(
                InvalidSectorIdentifier,
                match="Error deserializing sector_identifier_uri content",
            ):
                self.provider._verify_sector_identifier(rr)

        assert len(logcap.records) == 1
        assert logcap.records[0].msg == "sector_identifier_uri => %s"
        assert logcap.records[0].args == (body,)

    def test_verify_sector_identifier_ru_missing_in_si(self):
        """Redirect_uris is not present in the sector_identifier_uri content."""
        rr = RegistrationRequest(
            operation="register",
            sector_identifier_uri="https://example.com",
            redirect_uris=["http://example.com/missing"],
        )
        with responses.RequestsMock() as rsps, LogCapture(
            level=logging.DEBUG
        ) as logcap:
            rsps.add(
                rsps.GET,
                "https://example.com",
                body=json.dumps(["http://example.com/present"]),
            )
            with pytest.raises(
                InvalidSectorIdentifier,
                match="redirect_uri missing from sector_identifiers",
            ):
                self.provider._verify_sector_identifier(rr)

        assert len(logcap.records) == 2
        assert logcap.records[0].msg == "sector_identifier_uri => %s"
        assert logcap.records[0].args == ('["http://example.com/present"]',)
        assert logcap.records[1].msg == "redirect_uris: %s"
        assert logcap.records[1].args == (["http://example.com/missing"],)

    def test_verify_sector_identifier_ru_missing(self):
        """Redirect_uris is not present in the request."""
        rr = RegistrationRequest(
            operation="register", sector_identifier_uri="https://example.com"
        )
        redirects = ["http://example.com/present"]

        with responses.RequestsMock() as rsps, LogCapture(
            level=logging.DEBUG
        ) as logcap:
            rsps.add(rsps.GET, "https://example.com", body=json.dumps(redirects))
            si_redirects, si_url = self.provider._verify_sector_identifier(rr)

        assert si_url == "https://example.com"
        assert si_redirects == redirects
        assert len(logcap.records) == 1
        assert logcap.records[0].msg == "sector_identifier_uri => %s"
        assert logcap.records[0].args == ('["http://example.com/present"]',)

    def test_verify_sector_identifier_ru_ok(self):
        """Redirect_uris is present in the sector_identifier_uri content."""
        rr = RegistrationRequest(
            operation="register",
            sector_identifier_uri="https://example.com",
            redirect_uris=["http://example.com/present"],
        )
        redirects = ["http://example.com/present"]

        with responses.RequestsMock() as rsps, LogCapture(
            level=logging.DEBUG
        ) as logcap:
            rsps.add(rsps.GET, "https://example.com", body=json.dumps(redirects))
            si_redirects, si_url = self.provider._verify_sector_identifier(rr)

        assert si_url == "https://example.com"
        assert si_redirects == redirects
        assert len(logcap.records) == 2
        assert logcap.records[0].msg == "sector_identifier_uri => %s"
        assert logcap.records[0].args == ('["http://example.com/present"]',)
        assert logcap.records[1].msg == "redirect_uris: %s"
        assert logcap.records[1].args == (["http://example.com/present"],)

    @pytest.mark.parametrize(
        "uri",
        [
            "http://example.org/cb",
            "http://example.org/cb?got=you",
            "http://example.org/cb?foo=you" "http://example.org/cb?foo=bar&got=you",
            "http://example.org/cb?foo=you&foo=bar",
        ],
    )
    def test_registered_redirect_uri_faulty_with_query_component(self, uri):
        rr = RegistrationRequest(
            operation="register",
            redirect_uris=["http://example.org/cb?foo=bar"],
            response_types=["code"],
        )

        registration_req = rr.to_json()
        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)
        cid = regresp["client_id"]

        areq = AuthorizationRequest(
            redirect_uri=uri, client_id=cid, scope="openid", response_type="code"
        )

        with pytest.raises(RedirectURIError):
            self.provider._verify_redirect_uri(areq)

    def test_registered_redirect_uri_correct_with_query_component(self):
        rr = RegistrationRequest(
            operation="register",
            redirect_uris=["http://example.org/cb?foo=bar"],
            response_types=["code"],
        )

        registration_req = rr.to_json()
        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)
        cid = regresp["client_id"]

        areq = AuthorizationRequest(
            redirect_uri="http://example.org/cb?foo=bar",
            client_id=cid,
            scope="openid",
            response_type="code",
        )

        self.provider._verify_redirect_uri(areq)

    def test_verify_redirect_uri_native_http_localhost(self):
        areq = RegistrationRequest(
            redirect_uris=["http://localhost/cb"], application_type="native"
        )

        self.provider.verify_redirect_uris(areq)

    def test_verify_redirect_uri_native_loopback(self):
        areq = RegistrationRequest(
            redirect_uris=["http://127.0.0.1/cb"], application_type="native"
        )

        self.provider.verify_redirect_uris(areq)

    def test_verify_redirect_uri_native_http_non_localhost(self):
        areq = RegistrationRequest(
            redirect_uris=["http://example.org/cb"], application_type="native"
        )

        try:
            self.provider.verify_redirect_uris(areq)
        except InvalidRedirectURIError:
            assert True

    def test_verify_redirect_uri_native_custom(self):
        areq = RegistrationRequest(
            redirect_uris=["com.example.app:/oauth2redirect"], application_type="native"
        )

        self.provider.verify_redirect_uris(areq)

    def test_verify_redirect_uri_native_https(self):
        areq = RegistrationRequest(
            redirect_uris=["https://example.org/cb"], application_type="native"
        )

        try:
            self.provider.verify_redirect_uris(areq)
        except InvalidRedirectURIError:
            assert True

    def test_read_registration(self):
        rr = RegistrationRequest(
            operation="register",
            redirect_uris=["http://example.org/new"],
            response_types=["code"],
        )
        registration_req = rr.to_json()
        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)

        authn = " ".join(["Bearer", regresp["registration_access_token"]])
        query = "=".join(["client_id", regresp["client_id"]])
        resp = self.provider.read_registration(authn, query)

        assert json.loads(resp.message) == regresp.to_dict()

    def test_read_registration_malformed_authn(self):
        resp = self.provider.read_registration("wrong string", "request")
        assert resp.status_code == 400
        assert json.loads(resp.message) == {
            "error": "invalid_request",
            "error_description": None,
        }

    def test_read_registration_missing_clientid(self):
        resp = self.provider.read_registration("Bearer wrong string", "request")
        assert resp.status_code == 401

    def test_read_registration_wrong_cid(self):
        rr = RegistrationRequest(
            operation="register",
            redirect_uris=["http://example.org/new"],
            response_types=["code"],
        )
        registration_req = rr.to_json()
        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)

        authn = " ".join(["Bearer", regresp["registration_access_token"]])
        query = "=".join(["client_id", "123456789012"])
        resp = self.provider.read_registration(authn, query)

        assert resp.status_code == 401

    def test_read_registration_wrong_rat(self):
        rr = RegistrationRequest(
            operation="register",
            redirect_uris=["http://example.org/new"],
            response_types=["code"],
        )
        registration_req = rr.to_json()
        resp = self.provider.registration_endpoint(request=registration_req)
        regresp = RegistrationResponse().from_json(resp.message)

        authn = " ".join(["Bearer", "registration_access_token"])
        query = "=".join(["client_id", regresp["client_id"]])
        resp = self.provider.read_registration(authn, query)

        assert resp.status_code == 401

    def test_key_rollover(self):
        provider2 = Provider("FOOP", {}, {}, None, None, None, None, None)
        provider2.keyjar = KEYJAR
        # Number of KeyBundles
        assert len(provider2.keyjar.issuer_keys[""]) == 1
        kb = ec_init({"type": "EC", "crv": "P-256", "use": ["sig"]})
        provider2.do_key_rollover(json.loads(kb.jwks()), "b%d")
        assert len(provider2.keyjar.issuer_keys[""]) == 2
        kb = ec_init({"type": "EC", "crv": "P-256", "use": ["sig"]})
        provider2.do_key_rollover(json.loads(kb.jwks()), "b%d")
        assert len(provider2.keyjar.issuer_keys[""]) == 3
        provider2.remove_inactive_keys(-1)
        assert len(provider2.keyjar.issuer_keys[""]) == 2

    def test_end_session_endpoint(self):
        # End session not allowed if no cookie and no id_token_hint is sent
        # (can't determine session)
        resp = self.provider.end_session_endpoint("", cookie="FAIL")
        assert resp.status_code == 400

    def _create_cookie(self, user, client_id, c_type="sso"):
        cd = CookieDealer(self.provider)
        set_cookie = cd.create_cookie(
            "{}][{}".format(user, client_id), c_type, self.provider.sso_cookie_name
        )
        cookies_string = set_cookie[1]
        all_cookies: SimpleCookie = SimpleCookie()

        try:
            cookies_string = cookies_string.decode()
        except (AttributeError, UnicodeDecodeError):
            pass

        all_cookies.load(cookies_string)

        return all_cookies

    def _code_auth(self):
        state, location = self.cons.begin(
            "openid", "code", path="http://localhost:8087"
        )
        return self.provider.authorization_endpoint(request=location.split("?")[1])

    def _code_auth2(self):
        state, location = self.cons2.begin(
            "openid", "code", path="http://www.example.org"
        )
        return self.provider.authorization_endpoint(request=location.split("?")[1])

    def test_session_state_in_auth_req_for_session_support(self, session_db_factory):
        provider = Provider(
            SERVER_INFO["issuer"],
            session_db_factory(SERVER_INFO["issuer"]),
            CDB,
            AUTHN_BROKER,
            USERINFO,
            AUTHZ,
            verify_client,
            SYMKEY,
            urlmap=URLMAP,
            keyjar=KEYJAR,
        )

        provider.capabilities.update(
            {"check_session_iframe": "https://op.example.com/check_session"}
        )

        req_args = {
            "scope": ["openid"],
            "redirect_uri": "http://localhost:8087/authz",
            "response_type": ["code"],
            "client_id": "number5",
        }
        areq = AuthorizationRequest(**req_args)
        resp = provider.authorization_endpoint(request=areq.to_urlencoded())
        aresp = self.cons.parse_response(
            AuthorizationResponse, resp.message, sformat="urlencoded"
        )
        assert "session_state" in aresp

    def _assert_cookies_expired(self, http_headers):
        cookies_string = ";".join([c[1] for c in http_headers if c[0] == "Set-Cookie"])
        all_cookies: SimpleCookie = SimpleCookie()

        all_cookies.load(cookies_string)

        now = datetime.datetime.utcnow()
        for c in [self.provider.cookie_name, self.provider.session_cookie_name]:
            dt = datetime.datetime.strptime(
                all_cookies[c]["expires"], "%a, %d-%b-%Y %H:%M:%S GMT"
            )
            assert dt < now  # make sure the cookies have expired to be cleared

    def _auth_with_id_token(self):
        state, location = self.cons.begin(
            "openid", "id_token", path="http://localhost:8087"
        )
        resp = self.provider.authorization_endpoint(request=location.split("?")[1])
        aresp = self.cons.parse_response(
            AuthorizationResponse, resp.message, sformat="urlencoded"
        )
        return aresp["id_token"]

    def test_id_token_RS512_sign(self):
        self.provider.capabilities["id_token_signing_alg_values_supported"] = ["RS512"]
        self.provider.build_jwx_def()
        id_token = self._auth_with_id_token()
        assert id_token.jws_header["alg"] == "RS512"

    def test_refresh_token_grant_type_ok(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id=CLIENT_ID,
            response_type="code",
            scope=["openid", "offline_access"],
            prompt="consent",
        )

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        ae = AuthnEvent("user", "salt")
        _sdb[sid] = {
            "oauth_state": "authz",
            "authn_event": ae.to_json(),
            "authzreq": authreq.to_json(),
            "client_id": CLIENT_ID,
            "code": access_grant,
            "code_used": False,
            "scope": ["openid", "offline_access"],
            "redirect_uri": "http://example.com/authz",
        }
        _sdb.do_sub(sid, "client_salt")
        info = _sdb.upgrade_to_token(access_grant, issue_refresh=True)

        rareq = RefreshAccessTokenRequest(
            grant_type="refresh_token",
            refresh_token=info["refresh_token"],
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scope=["openid"],
        )

        resp = self.provider.refresh_token_grant_type(rareq)
        atr = AccessTokenResponse().deserialize(resp.message, "json")
        assert atr["refresh_token"] is not None
        assert atr["token_type"] == "Bearer"

    def test_refresh_token_grant_type_wrong_token(self):
        rareq = RefreshAccessTokenRequest(
            grant_type="refresh_token",
            refresh_token="some_other_refresh_token",
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scope=["openid"],
        )

        resp = self.provider.refresh_token_grant_type(rareq)
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert atr["error"] == "invalid_request"
        assert atr["error_description"] == "Not a refresh token"

    def test_refresh_token_grant_type_expired(self):
        authreq = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id=CLIENT_ID,
            response_type="code",
            scope=["openid", "offline_access"],
            prompt="consent",
        )

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.access_token(sid=sid)
        ae = AuthnEvent("user", "salt")
        _sdb[sid] = {
            "oauth_state": "authz",
            "authn_event": ae.to_json(),
            "authzreq": authreq.to_json(),
            "client_id": CLIENT_ID,
            "code": access_grant,
            "code_used": False,
            "scope": ["openid", "offline_access"],
            "redirect_uri": "http://example.com/authz",
        }
        _sdb.do_sub(sid, "client_salt")
        with freeze_time("2000-01-01"):
            info = _sdb.upgrade_to_token(access_grant, issue_refresh=True)

        rareq = RefreshAccessTokenRequest(
            grant_type="refresh_token",
            refresh_token=info["refresh_token"],
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            scope=["openid"],
        )

        resp = self.provider.refresh_token_grant_type(rareq)
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert atr["error"] == "invalid_request"
        assert atr["error_description"] == "Refresh token is expired"

    def test_authorization_endpoint_faulty_request_uri(self):
        bib = {
            "scope": ["openid"],
            "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
            "redirect_uri": "http://localhost:8087/authz",
            "request_uri": "https://some-non-resolving.hostname.com/request_uri#1234",
            # faulty request_uri
            "response_type": ["code"],
            "client_id": "a1b2c3",
        }

        arq = AuthorizationRequest(**bib)
        resp = self.provider.authorization_endpoint(request=arq.to_urlencoded())
        assert resp.status_code == 400
        msg = json.loads(resp.message)
        assert msg["error"] == "invalid_request_uri"

    def test_encrypt_missing_info(self):
        payload = self.provider.encrypt("payload", {}, "some_client")
        assert payload == "payload"

    def test_encrypt_missing_recuperated(self):
        self.provider.keyjar = KeyJar()  # Empty keyjar, all keys are lost
        with open(os.path.join(BASE_PATH, "jwk_enc.json")) as keyf:
            key = keyf.read()
        info = {
            "id_token_encrypted_response_alg": "A128KW",
            "id_token_encrypted_response_enc": "A128CBC-HS256",
            "client_secret": "some_secret",
            "jwks_uri": "http://example.com/key",
        }
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                "http://example.com/key",
                body=key,
                content_type="application/json",
            )
            payload = self.provider.encrypt("payload", info, "some_client")
        token = JWEnc().unpack(payload)
        headers = json.loads(token.protected_header().decode())
        assert headers["alg"] == "A128KW"
        assert headers["enc"] == "A128CBC-HS256"

    def test_encrypt_missing_not_recuperated(self):
        self.provider.keyjar = KeyJar()  # Empty keyjar, all keys are lost
        info = {
            "id_token_encrypted_response_alg": "RSA1_5",
            "id_token_encrypted_response_enc": "A128CBC-HS256",
            "client_secret": "some_secret",
        }
        with pytest.raises(JWEException):
            self.provider.encrypt("payload", info, "some_client")

    def test_encrypt_userinfo_missing_recuperated(self):
        self.provider.keyjar = KeyJar()  # Empty keyjar, all keys are lost
        with open(os.path.join(BASE_PATH, "jwk_enc.json")) as keyf:
            key = keyf.read()
        info = {
            "userinfo_encrypted_response_alg": "A128KW",
            "userinfo_encrypted_response_enc": "A128CBC-HS256",
            "client_secret": "some_secret",
            "jwks_uri": "http://example.com/key",
        }
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                "http://example.com/key",
                body=key,
                content_type="application/json",
            )
            payload = self.provider.encrypt(
                "payload", info, "some_client", val_type="userinfo"
            )
        token = JWEnc().unpack(payload)
        headers = json.loads(token.protected_header().decode())
        assert headers["alg"] == "A128KW"
        assert headers["enc"] == "A128CBC-HS256"

    def test_encrypt_missing_userinfo_not_recuperated(self):
        self.provider.keyjar = KeyJar()  # Empty keyjar, all keys are lost
        info = {
            "userinfo_encrypted_response_alg": "RSA1_5",
            "userinfo_encrypted_response_enc": "A128CBC-HS256",
            "client_secret": "some_secret",
        }
        with pytest.raises(JWEException):
            self.provider.encrypt("payload", info, "some_client", val_type="userinfo")

    def test_recuperate_jwks(self):
        self.provider.keyjar = KeyJar()  # Empty keyjar, all keys are lost
        with open(os.path.join(BASE_PATH, "jwk_enc.json")) as keyf:
            key = keyf.read()
        info = {
            "id_token_encrypted_response_alg": "A128KW",
            "id_token_encrypted_response_enc": "A128CBC-HS256",
            "client_secret": "some_secret",
            "jwks": json.loads(key),
        }
        self.provider.recuperate_keys("some_client", info)
        assert len(self.provider.keyjar.get_issuer_keys("some_client")) == 3

    def test_recuperate_jwks_uri(self):
        self.provider.keyjar = KeyJar()  # Empty keyjar, all keys are lost
        with open(os.path.join(BASE_PATH, "jwk_enc.json")) as keyf:
            key = keyf.read()
        info = {
            "id_token_encrypted_response_alg": "A128KW",
            "id_token_encrypted_response_enc": "A128CBC-HS256",
            "client_secret": "some_secret",
            "jwks_uri": "http://example.com/key",
        }
        with responses.RequestsMock() as rsps:
            rsps.add(
                responses.GET,
                "http://example.com/key",
                body=key,
                content_type="application/json",
            )
            self.provider.recuperate_keys("some_client", info)
            assert len(self.provider.keyjar.get_issuer_keys("some_client")) == 3

    def test_recuperate_none(self):
        self.provider.keyjar = KeyJar()  # Empty keyjar, all keys are lost
        info = {
            "id_token_encrypted_response_alg": "A128KW",
            "id_token_encrypted_response_enc": "A128CBC-HS256",
            "client_secret": "some_secret",
        }
        self.provider.recuperate_keys("some_client", info)
        assert len(self.provider.keyjar.get_issuer_keys("some_client")) == 2

    def test_get_by(self):
        _sdb = self.provider.sdb

        # First authn
        authreq_1 = AuthorizationRequest(
            state="state",
            redirect_uri="http://example.com/authz",
            client_id=CLIENT_ID,
            response_type="code",
            scope=["openid", "offline_access"],
            prompt="consent",
        )

        sid = _sdb.access_token.key(user="sub", areq=authreq_1)
        access_grant = _sdb.access_token(sid=sid)
        ae = AuthnEvent("user", "salt")
        _sdb[sid] = {
            "oauth_state": "authz",
            "authn_event": ae.to_json(),
            "authzreq": authreq_1.to_json(),
            "client_id": CLIENT_ID,
            "code": access_grant,
            "code_used": False,
            "scope": ["openid", "offline_access"],
            "redirect_uri": "http://example.com/authz",
        }
        _sdb.do_sub(sid, "client_salt")
        _sdb.upgrade_to_token(access_grant, issue_refresh=True)

        # Second authn
        authreq_2 = AuthorizationRequest(
            state="next_state",
            redirect_uri="http://example.com/authz",
            client_id=CLIENT_ID,
            response_type="code",
            scope=["openid", "offline_access"],
        )

        sid_2 = _sdb.access_token.key(user="sub", areq=authreq_2)
        access_grant = _sdb.access_token(sid=sid_2)
        ae = AuthnEvent("user", "salt")
        _sdb[sid_2] = {
            "oauth_state": "authz",
            "authn_event": ae.to_json(),
            "authzreq": authreq_1.to_json(),
            "client_id": "2ndClient",
            "code": access_grant,
            "code_used": False,
            "scope": ["openid", "offline_access"],
            "redirect_uri": "http://example.com/authz",
        }
        _sdb.do_sub(sid_2, "client_salt")
        _sdb.upgrade_to_token(access_grant, issue_refresh=True)

        sub = _sdb[sid_2]["sub"]
        assert self.provider.sdb.get_uid_by_sub(sub) == "user"
        assert self.provider.sdb.get_uid_by_sid(sid_2) == "user"

        assert self.provider.get_by_sub_and_(sub, "client_id", "2ndClient") == sid_2
        assert self.provider.get_by_sub_and_(sub, "client_id", CLIENT_ID) == sid

        # Error cases
        assert self.provider.get_by_sub_and_(sub, "client_id", "unknown") is None
        assert self.provider.get_by_sub_and_("who", "client_id", CLIENT_ID) is None
        assert self.provider.get_by_sub_and_(sub, "foo", "bar") is None
