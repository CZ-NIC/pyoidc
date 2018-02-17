from future.backports.urllib.parse import urlparse

import json
import os

import pytest
import responses
from jwkest import BadSignature
from jwkest.jwk import SYMKey

from oic.oauth2.message import MissingSigningKey
from oic.oic import DEF_SIGN_ALG
from oic.oic import Server
from oic.oic import response_types_to_grant_types
from oic.oic.consumer import IGNORE
from oic.oic.consumer import Consumer
from oic.oic.consumer import clean_response
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthorizationResponse
from oic.oic.message import IdToken
from oic.oic.message import OpenIDSchema
from oic.oic.message import ProviderConfigurationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.keyio import keybundle_from_local_file
from oic.utils.time_util import utc_time_sans_frac

__author__ = 'rohe0002'

KC_SYM_VS = KeyBundle({"kty": "oct", "key": "abcdefghijklmnop", "use": "ver"})
KC_SYM_S = KeyBundle({"kty": "oct", "key": "abcdefghijklmnop", "use": "sig"})

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))
KC_RSA = keybundle_from_local_file(os.path.join(BASE_PATH, "rsa.key"), "rsa",
                                   ["ver", "sig"])

SRVKEYS = KeyJar()
SRVKEYS[""] = [KC_RSA]
SRVKEYS["client_1"] = [KC_SYM_VS, KC_RSA]

CLIKEYS = KeyJar()
CLIKEYS["http://localhost:8088"] = [KC_RSA]
CLIKEYS[""] = [KC_RSA, KC_SYM_VS]
CLIKEYS["http://example.com"] = [KC_RSA]

SERVER_INFO = {
    "version": "3.0",
    "issuer": "https://localhost:8088",
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    "userinfo_endpoint": "http://localhost:8088/userinfo",
    "flows_supported": ["code", "token"],
}

CONFIG = {
    "authz_page": "authz",
    "scope": ["openid"],
    "response_type": "code",
    "request_method": "parameter",
    "password": "hemligt",
    "max_age": 3600,
    "user_info": {
        "name": None,
    }
}


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_response_types_to_grant_types():
    req_args = ['code']
    assert set(
        response_types_to_grant_types(req_args)) == {'authorization_code'}
    req_args = ['code', 'code id_token']
    assert set(
        response_types_to_grant_types(req_args)) == {'authorization_code',
                                                     'implicit'}
    req_args = ['code', 'id_token code', 'code token id_token']
    assert set(
        response_types_to_grant_types(req_args)) == {'authorization_code',
                                                     'implicit'}

    with pytest.raises(ValueError):
        response_types_to_grant_types(['foobar openid'])


def test_clean_response():
    atr = AccessTokenResponse(access_token="access_token",
                              token_type="bearer", expires_in=600,
                              refresh_token="refresh", steps=39, stalls="yes")

    catr = clean_response(atr)
    atr_keys = atr.keys()
    catr_keys = catr.keys()
    assert _eq(atr_keys, ['token_type', 'access_token', 'expires_in',
                          'refresh_token', 'steps', 'stalls'])
    assert _eq(catr_keys, ['token_type', 'access_token', 'expires_in',
                           'refresh_token'])


class TestOICConsumer():
    @pytest.fixture(autouse=True)
    def setup_consumer(self, fake_oic_server, session_db_factory):
        client_id = "client_1"
        client_config = {
            "client_id": client_id,
            "client_authn_method": CLIENT_AUTHN_METHOD,
            # 'config': {}
        }

        self.consumer = Consumer(session_db_factory(SERVER_INFO["issuer"]),
                                 CONFIG, client_config, SERVER_INFO)
        self.consumer.behaviour = {
            "request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]}
        self.consumer.client_secret = "abcdefghijklmnop"
        self.consumer.keyjar = CLIKEYS
        self.consumer.redirect_uris = ["https://example.com/cb"]
        self.consumer.authorization_endpoint = \
            "http://example.com/authorization"
        self.consumer.token_endpoint = "http://example.com/token"
        self.consumer.userinfo_endpoint = "http://example.com/userinfo"
        self.consumer.client_secret = "hemlig"
        self.consumer.secret_type = "basic"

        mfos = fake_oic_server("http://localhost:8088")
        mfos.keyjar = SRVKEYS
        self.consumer.http_request = mfos.http_request

    def test_backup_keys(self):
        keys = self.consumer.__dict__.keys()
        _dict = self.consumer.dictionary()
        dkeys = [key for key in keys if key not in _dict.keys()]
        assert _eq(dkeys, IGNORE)

    def test_backup_restore(self):
        authz_org_url = "http://example.org/authorization"

        _dict = sorted(list(self.consumer.__dict__.items()))

        self.consumer._backup("sid")
        self.consumer.restore("sid")
        assert sorted(_dict) == sorted(list(self.consumer.__dict__.items()))

        self.consumer.authorization_endpoint = authz_org_url
        assert _dict != sorted(list(self.consumer.__dict__.items()))

        self.consumer.restore("sid")
        assert _dict == sorted(list(self.consumer.__dict__.items()))

    def test_backup_restore_update(self):
        authz_org_url = "http://example.org/authorization"

        self.consumer._backup("sid")

        self.consumer.authorization_endpoint = authz_org_url
        self.consumer.token_endpoint = "http://example.org/token"
        self.consumer.userinfo_endpoint = ""

        assert self.consumer.authorization_endpoint == authz_org_url
        assert self.consumer.token_endpoint == "http://example.org/token"
        assert self.consumer.userinfo_endpoint == ""

        self.consumer.update("sid")

        assert self.consumer.authorization_endpoint == authz_org_url
        assert self.consumer.token_endpoint == "http://example.org/token"
        assert self.consumer.userinfo_endpoint == "http://example.com/userinfo"

    def test_begin(self):
        srv = Server()
        srv.keyjar = SRVKEYS
        sid, location = self.consumer.begin("openid", "code")
        authreq = srv.parse_authorization_request(url=location)
        assert _eq(list(authreq.keys()),
                   ['state', 'max_age', 'claims', 'response_type', 'client_id',
                    'scope', 'redirect_uri'])

        assert authreq["state"] == sid
        assert authreq["scope"] == self.consumer.consumer_config["scope"]
        assert authreq["client_id"] == self.consumer.client_id

    def test_begin_file(self, tmpdir):
        path = tmpdir.strpath
        external_path = "/exported"
        self.consumer.consumer_config["request_method"] = "file"
        self.consumer.consumer_config["temp_dir"] = path
        self.consumer.consumer_config["temp_path"] = external_path
        self.consumer.consumer_config["authz_page"] = "/authz"
        srv = Server()
        srv.keyjar = SRVKEYS

        sid, location = self.consumer.begin("openid", "code",
                                            path="http://localhost:8087")

        with responses.RequestsMock() as rsps:
            p = urlparse(self.consumer.request_uri)
            assert p.netloc == "localhost:8087"
            # Map the URL path to the local path
            relative_path = os.path.relpath(p.path, external_path)
            file_path = os.path.join(path, relative_path)

            rsps.add(rsps.GET, self.consumer.request_uri,
                     body=open(file_path).read(), status=200,
                     content_type='application/urlencoded')

            authreq = srv.parse_authorization_request(url=location)
            assert _eq(list(authreq.keys()),
                       ['max_age', 'state', 'redirect_uri', 'response_type',
                        'client_id', 'scope', 'claims'])

            assert authreq["state"] == sid
            assert authreq["scope"] == self.consumer.consumer_config["scope"]
            assert authreq["client_id"] == self.consumer.client_id
            assert authreq["redirect_uri"].startswith(
                "http://localhost:8087/authz")

    def test_complete(self):
        _state = "state0"
        args = {
            "client_id": self.consumer.client_id,
            "response_type": "code",
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(
            state=_state, request_args=args)
        assert result.status_code == 302
        parsed = urlparse(result.headers["location"])
        baseurl = "{}://{}{}".format(parsed.scheme, parsed.netloc, parsed.path)
        assert baseurl == self.consumer.redirect_uris[0]

        self.consumer.parse_response(AuthorizationResponse, info=parsed.query,
                                     sformat="urlencoded")

        resp = self.consumer.complete(_state)
        assert isinstance(resp, AccessTokenResponse)
        assert _eq(resp.keys(),
                   ['token_type', 'state', 'access_token', 'scope'])

        assert resp["state"] == _state

    def test_parse_authz(self):
        _state = "state0"
        args = {
            "client_id": self.consumer.client_id,
            "response_type": "code",
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(
            state=_state, request_args=args)
        self.consumer._backup(_state)

        part = self.consumer.parse_authz(query=result.headers["location"])
        atr = part[0]
        assert part[1] is None
        assert part[2] is None

        assert isinstance(atr, AuthorizationResponse)
        assert atr["state"] == _state
        assert "code" in atr

    def test_parse_authz_implicit(self):
        self.consumer.consumer_config["response_type"] = ["token"]
        _state = "statxxx"
        args = {
            "client_id": self.consumer.client_id,
            "response_type": "implicit",
            "scope": ["openid"],
            "redirect_uri": "http://localhost:8088/cb"
        }

        result = self.consumer.do_authorization_request(
            state=_state, request_args=args)

        part = self.consumer.parse_authz(query=result.headers["location"])
        assert part[0] is None
        atr = part[1]
        assert part[2] is None

        assert isinstance(atr, AccessTokenResponse)
        assert atr["state"] == _state
        assert "access_token" in atr

    def test_complete_secret_auth(self):
        _state = "state0"
        del self.consumer.consumer_config["password"]

        args = {
            "client_id": self.consumer.client_id,
            "response_type": "code",
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(state=_state,
                                                        request_args=args)
        assert result.status_code == 302
        parsed = urlparse(result.headers["location"])
        baseurl = "{}://{}{}".format(parsed.scheme, parsed.netloc, parsed.path)
        assert baseurl == self.consumer.redirect_uris[0]

        self.consumer.parse_response(AuthorizationResponse, info=parsed.query,
                                     sformat="urlencoded")

        resp = self.consumer.complete(_state)
        assert isinstance(resp, AccessTokenResponse)
        assert _eq(resp.keys(),
                   ['token_type', 'state', 'access_token', 'scope'])

        assert resp["state"] == _state

    def test_complete_auth_token(self):
        _state = "state0"
        self.consumer.consumer_config["response_type"] = ["code", "token"]

        args = {
            "client_id": self.consumer.client_id,
            "response_type": self.consumer.consumer_config["response_type"],
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(state=_state,
                                                        request_args=args)
        self.consumer._backup("state0")

        assert result.status_code == 302
        parsed = urlparse(result.headers["location"])
        baseurl = "{}://{}{}".format(parsed.scheme, parsed.netloc, parsed.path)
        assert baseurl == self.consumer.redirect_uris[0]

        part = self.consumer.parse_authz(query=parsed.query)
        auth = part[0]
        acc = part[1]
        assert part[2] is None

        assert isinstance(auth, AuthorizationResponse)
        assert isinstance(acc, AccessTokenResponse)
        print(auth.keys())
        assert _eq(auth.keys(), ['code', 'access_token',
                                 'token_type', 'state', 'client_id', 'scope'])
        assert _eq(acc.keys(), ['token_type', 'state', 'access_token', 'scope'])

    def test_complete_auth_token_idtoken(self):
        _state = "state0"
        self.consumer.consumer_config["response_type"] = ["id_token", "token"]
        self.consumer.registration_response = {
            "id_token_signed_response_alg": "RS256",
        }
        self.consumer.provider_info = {
            "issuer": "http://localhost:8088"}  # abs min
        self.consumer.authz_req = {}  # Store AuthzReq with state as key

        args = {
            "client_id": self.consumer.client_id,
            "response_type": self.consumer.consumer_config["response_type"],
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(state=_state,
                                                        request_args=args)
        assert result.status_code == 302
        parsed = urlparse(result.headers["location"])
        baseurl = "{}://{}{}".format(parsed.scheme, parsed.netloc, parsed.path)
        assert baseurl == self.consumer.redirect_uris[0]

        part = self.consumer.parse_authz(query=parsed.query,
                                         algs=self.consumer.sign_enc_algs(
                                             "id_token"))
        auth = part[0]
        atr = part[1]
        assert part[2] is None

        assert auth is None
        assert isinstance(atr, AccessTokenResponse)
        assert _eq(atr.keys(), ['access_token', 'id_token',
                                'token_type', 'state', 'scope'])

        self.consumer.verify_id_token(atr["id_token"],
                                      self.consumer.authz_req[atr["state"]])

    def test_userinfo(self):
        _state = "state0"

        args = {
            "client_id": self.consumer.client_id,
            "response_type": "code",
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(state=_state,
                                                        request_args=args)
        assert result.status_code == 302
        parsed = urlparse(result.headers["location"])
        baseurl = "{}://{}{}".format(parsed.scheme, parsed.netloc, parsed.path)
        assert baseurl == self.consumer.redirect_uris[0]

        self.consumer.parse_response(AuthorizationResponse, info=parsed.query,
                                     sformat="urlencoded")

        self.consumer.complete(_state)

        result = self.consumer.get_user_info(_state)
        assert isinstance(result, OpenIDSchema)
        assert _eq(result.keys(),
                   ['name', 'email', 'verified', 'nickname', 'sub'])

    def test_sign_userinfo(self):
        _state = "state0"
        self.consumer.client_prefs = {"userinfo_signed_response_alg": "RS256"}
        self.consumer.provider_info = {
            "userinfo_endpoint": "http://localhost:8088/userinfo",
            "issuer": "http://localhost:8088/"}
        del self.consumer.consumer_config["request_method"]

        args = {
            "client_id": self.consumer.client_id,
            "response_type": "code",
            "scope": ["openid"],
        }

        self.consumer.begin("openid", "code")
        result = self.consumer.do_authorization_request(state=_state,
                                                        request_args=args)
        parsed = urlparse(result.headers["location"])
        self.consumer.parse_response(AuthorizationResponse, info=parsed.query,
                                     sformat="urlencoded")

        self.consumer.complete(_state)

        result = self.consumer.get_user_info(_state)
        assert isinstance(result, OpenIDSchema)
        assert _eq(result.keys(),
                   ['name', 'email', 'verified', 'nickname', 'sub'])

    def real_test_discover(self):
        c = Consumer(None, None)
        principal = "nav@connect-op.heroku.com"
        res = c.discover(principal)
        assert isinstance(res, ProviderConfigurationResponse)
        assert _eq(res.keys(), ['registration_endpoint', 'scopes_supported',
                                'identifiers_supported', 'token_endpoint',
                                'flows_supported', 'version',
                                'userinfo_endpoint',
                                'authorization_endpoint', 'x509_url', 'issuer'])
        assert res.version == "3.0"
        assert _eq(res.flows_supported, ['code', 'token', 'id_token',
                                         'code token', 'code id_token',
                                         'id_token token'])

    def test_discover(self, fake_oic_server):
        c = Consumer(None, None)
        mfos = fake_oic_server("https://localhost:8088")
        mfos.keyjar = SRVKEYS
        c.http_request = mfos.http_request

        principal = "foo@example.com"
        res = c.discover(principal)
        assert res == "https://localhost:8088/"

    def test_provider_config(self, fake_oic_server):
        c = Consumer(None, None)
        mfos = fake_oic_server("https://example.com")
        mfos.keyjar = SRVKEYS
        c.http_request = mfos.http_request

        principal = "foo@example.com"

        res = c.discover(principal)
        info = c.provider_config(res)
        assert isinstance(info, ProviderConfigurationResponse)
        assert _eq(info.keys(), ['registration_endpoint', 'jwks_uri',
                                 'check_session_endpoint',
                                 'refresh_session_endpoint',
                                 'register_endpoint',
                                 'subject_types_supported',
                                 'token_endpoint_auth_methods_supported',
                                 'id_token_signing_alg_values_supported',
                                 'grant_types_supported', 'user_info_endpoint',
                                 'claims_parameter_supported',
                                 'request_parameter_supported',
                                 'discovery_endpoint', 'issuer',
                                 'authorization_endpoint', 'scopes_supported',
                                 'require_request_uri_registration',
                                 'identifiers_supported', 'token_endpoint',
                                 'request_uri_parameter_supported', 'version',
                                 'response_types_supported',
                                 'end_session_endpoint', 'flows_supported'])

        assert info["end_session_endpoint"] == "https://example.com/end_session"

    def test_client_register(self, fake_oic_server):
        c = Consumer(None, None)

        c.application_type = "web"
        c.application_name = "My super service"
        c.redirect_uris = ["https://example.com/authz"]
        c.contact = ["foo@example.com"]
        mfos = fake_oic_server("https://example.com")
        mfos.keyjar = SRVKEYS
        c.http_request = mfos.http_request
        location = c.discover("foo@example.com")
        info = c.provider_config(location)

        c.register(info["registration_endpoint"])
        assert c.client_id is not None
        assert c.client_secret is not None
        assert c.registration_expires > utc_time_sans_frac()

    def _faulty_id_token(self):
        idval = {'nonce': 'KUEYfRM2VzKDaaKD', 'sub': 'EndUserSubject',
                 'iss': 'https://alpha.cloud.nds.rub.de', 'exp': 1420823073,
                 'iat': 1420822473, 'aud': 'TestClient'}
        idts = IdToken(**idval)

        _signed_jwt = idts.to_jwt(key=[SYMKey(key="TestPassword")],
                                  algorithm="HS256")

        # Mess with the signed id_token
        p = _signed_jwt.split(".")
        p[2] = "aaa"

        return ".".join(p)

    def test_faulty_id_token(self):
        _faulty_signed_jwt = self._faulty_id_token()

        with pytest.raises(BadSignature):
            IdToken().from_jwt(_faulty_signed_jwt,
                               key=[SYMKey(key="TestPassword")])

        # What if no verification key is given ?
        # Should also result in an exception
        with pytest.raises(MissingSigningKey):
            IdToken().from_jwt(_faulty_signed_jwt)

    def test_faulty_id_token_in_access_token_response(self):
        c = Consumer(None, None)
        c.keyjar.add_symmetric("", "TestPassword", ["sig"])

        _info = {"access_token": "accessTok",
                 "id_token": self._faulty_id_token(),
                 "token_type": "Bearer"}

        _json = json.dumps(_info)
        with pytest.raises(BadSignature):
            c.parse_response(AccessTokenResponse, _json, sformat="json")

    def test_faulty_idtoken_from_accesstoken_endpoint(self, mitm_server):
        mfos = mitm_server("http://localhost:8088")
        mfos.keyjar = SRVKEYS
        self.consumer.http_request = mfos.http_request
        _state = "state0"
        self.consumer.consumer_config["response_type"] = ["id_token"]

        args = {
            "client_id": self.consumer.client_id,
            "response_type": self.consumer.consumer_config["response_type"],
            "scope": ["openid"],
        }

        result = self.consumer.do_authorization_request(state=_state,
                                                        request_args=args)
        self.consumer._backup("state0")

        assert result.status_code == 302
        query = urlparse(result.headers["location"]).query
        with pytest.raises(BadSignature):
            self.consumer.parse_authz(query=query)
