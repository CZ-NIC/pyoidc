#!/usr/bin/env python
import json
import os
import time
from collections import Counter
from urllib.parse import urlparse

import pytest
from jwkest.jws import alg2keytype
from jwkest.jws import left_hash
from jwkest.jwt import JWT
from requests import Response

from oic.exception import RegistrationError
from oic.oauth2.exception import OtherError
from oic.oic import DEF_SIGN_ALG
from oic.oic import Client
from oic.oic import Grant
from oic.oic import Server
from oic.oic import Token
from oic.oic import scope2claims
from oic.oic.message import SCOPE2CLAIMS
from oic.oic.message import SINGLE_OPTIONAL_STRING
from oic.oic.message import AccessTokenRequest
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AuthorizationResponse
from oic.oic.message import CheckSessionRequest
from oic.oic.message import Claims
from oic.oic.message import ClaimsRequest
from oic.oic.message import EndSessionRequest
from oic.oic.message import IdToken
from oic.oic.message import OpenIDRequest
from oic.oic.message import OpenIDSchema
from oic.oic.message import RefreshAccessTokenRequest
from oic.oic.message import RefreshSessionRequest
from oic.oic.message import RegistrationRequest
from oic.oic.message import UserInfoRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.keyio import rsa_load
from oic.utils.time_util import utc_time_sans_frac

__author__ = 'rohe0002'

KC_SYM_S = KeyBundle(
    {"kty": "oct", "key": "abcdefghijklmnop".encode("utf-8"), "use": "sig",
     "alg": "HS256"})

BASE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "data/keys"))
_key = rsa_load(os.path.join(BASE_PATH, "rsa.key"))
KC_RSA = KeyBundle({"key": _key, "kty": "RSA", "use": "sig"})

KEYJ = KeyJar()
KEYJ[""] = [KC_RSA, KC_SYM_S]
KEYJ["client_1"] = [KC_RSA, KC_SYM_S]

CLIENT_ID = "client_1"
IDTOKEN = IdToken(iss="http://oic.example.org/", sub="sub",
                  aud=CLIENT_ID, exp=utc_time_sans_frac() + 86400,
                  nonce="N0nce",
                  iat=time.time())


def _eq(l1, l2):
    return set(l1) == set(l2)


# ----------------- CLIENT --------------------


class TestClient(object):
    @pytest.fixture(autouse=True)
    def create_client(self, fake_oic_server):
        self.redirect_uri = "http://example.com/redirect"
        self.client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)
        self.client.redirect_uris = [self.redirect_uri]
        self.client.authorization_endpoint = "http://example.com/authorization"
        self.client.token_endpoint = "http://example.com/token"
        self.client.userinfo_endpoint = "http://example.com/userinfo"
        self.client.check_session_endpoint = "https://example.com/check_session"
        self.client.client_secret = "abcdefghijklmnop"
        self.client.keyjar[""] = KC_RSA
        self.client.behaviour = {
            "request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]}
        self.mfos = fake_oic_server("http://example.com")
        self.mfos.keyjar = KEYJ
        self.client.http_request = self.mfos.http_request

    def test_construct_authz_req_with_request_object(self, tmpdir):
        path = tmpdir.strpath
        request_uri_args = {
            "local_dir": path,
            "base_path": "http://example.com/"
        }
        areq = self.client.construct_AuthorizationRequest(request_method="file",
                                                          **request_uri_args)
        p = urlparse(areq["request_uri"])
        local_path = os.path.join(path, p.path.lstrip("/"))
        with open(local_path) as f:
            data = f.read()
        jwt = JWT().unpack(data)
        payload = jwt.payload()

        assert payload["redirect_uri"] == "http://example.com/redirect"
        assert payload["client_id"] == CLIENT_ID
        assert "nonce" in payload

        os.remove(local_path)

    def test_construct_authz_req_nonce_for_token(self):
        assert "nonce" in self.client.construct_AuthorizationRequest(
            response_type="token")
        assert "nonce" in self.client.construct_AuthorizationRequest(
            response_type="id_token")
        assert "nonce" in self.client.construct_AuthorizationRequest(
            response_type="token id_token")

    def test_do_authorization_request(self):
        args = {"response_type": ["code"], "scope": "openid"}
        result = self.client.do_authorization_request(state="state0",
                                                      request_args=args)
        assert result.status_code == 302
        _loc = result.headers["location"]
        assert _loc.startswith(self.client.redirect_uris[0])
        _, query = _loc.split("?")

        self.client.parse_response(AuthorizationResponse, info=query,
                                   sformat="urlencoded")

    def test_access_token_request(self):
        args = {"response_type": ["code"],
                "scope": ["openid"]}
        r = self.client.do_authorization_request(state="state0",
                                                 request_args=args)
        self.client.parse_response(AuthorizationResponse, r.headers["location"],
                                   sformat="urlencoded")

        resp = self.client.do_access_token_request(scope="openid",
                                                   state="state0")
        assert isinstance(resp, AccessTokenResponse)
        assert _eq(resp.keys(),
                   ['token_type', 'state', 'access_token', 'scope'])

    def test_access_token_request_with_custom_response_class(self):
        args = {"response_type": ["code"],
                "scope": ["openid"]}
        r = self.client.do_authorization_request(state="state0",
                                                 request_args=args)

        self.client.parse_response(AuthorizationResponse, r.headers["location"],
                                   sformat="urlencoded")

        # AccessTokenResponse wrapper class
        class AccessTokenResponseWrapper(AccessTokenResponse):
            c_param = AccessTokenResponse.c_param.copy()
            c_param.update({"raw_id_token": SINGLE_OPTIONAL_STRING})

            def __init__(self, *args, **kwargs):
                super(AccessTokenResponseWrapper, self).__init__(*args, **kwargs)
                self["raw_id_token"] = None

            def verify(self, **kwargs):
                if "id_token" in self:
                    self["raw_id_token"] = self["id_token"]
                return super(AccessTokenResponseWrapper, self).verify(**kwargs)

        resp = \
            self.client.do_access_token_request(scope="openid",
                                                state="state0",
                                                response_cls=AccessTokenResponseWrapper)

        assert isinstance(resp, AccessTokenResponse)
        assert isinstance(resp, AccessTokenResponseWrapper)
        assert _eq(resp.keys(),
                   ['token_type', 'state', 'access_token', 'scope',
                    'raw_id_token'])
        assert len(self.client.grant["state0"].tokens) == 1

    def test_do_user_info_request(self):
        resp = AuthorizationResponse(code="code", state="state")
        grant = Grant(10)  # expired grant
        grant.add_code(resp)
        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access",
                                   token_type="Bearer")
        token = Token(resp)
        grant.tokens.append(token)
        self.client.grant["state0"] = grant

        resp = self.client.do_user_info_request(state="state0")
        assert isinstance(resp, OpenIDSchema)
        assert _eq(resp.keys(),
                   ['name', 'email', 'verified', 'nickname', 'sub'])
        assert resp["name"] == "Melody Gardot"

    def test_do_access_token_refresh(self):
        args = {"response_type": ["code"],
                "scope": ["openid", "offline_access"],
                "prompt": ["consent"]}
        r = self.client.do_authorization_request(state="state0",
                                                 request_args=args)
        self.client.parse_response(AuthorizationResponse, r.headers["location"],
                                   sformat="urlencoded")
        self.client.do_access_token_request(scope="openid offline_access",
                                            state="state0")

        resp = self.client.do_access_token_refresh(
            scope="openid offline_access",
            state="state0")
        assert len(self.client.grant['state0'].tokens) == 1
        assert isinstance(resp, AccessTokenResponse)
        assert _eq(resp.keys(), ['token_type', 'access_token', 'refresh_token',
                                 'scope', 'state'])

    def test_client_id(self):
        resp = AuthorizationResponse(code="code",
                                     state="stateX").to_urlencoded()
        self.client.parse_response(AuthorizationResponse, resp,
                                   sformat="urlencoded")
        args = {
            "code": "code",
            "redirect_uri": self.client.redirect_uris[0],
            "client_id": self.client.client_id,
        }

        url, query, ht_args, cis = self.client.request_info(
            AccessTokenRequest, method="POST", request_args=args,
            state='stateX', authn_method='client_secret_basic',
            grant_type='authorization_code')

        assert 'client_id' not in cis

        args = {
            "code": "code",
            "redirect_uri": self.client.redirect_uris[0],
        }

        url, query, ht_args, cis = self.client.request_info(
            AccessTokenRequest, method="POST", request_args=args,
            state='stateX', authn_method='client_secret_basic',
            grant_type='authorization_code')

        assert 'client_id' not in cis

    def test_do_check_session_request(self):
        # RSA signing
        alg = "RS256"
        ktyp = alg2keytype(alg)
        _sign_key = self.client.keyjar.get_signing_key(ktyp)
        args = {"id_token": IDTOKEN.to_jwt(key=_sign_key, algorithm=alg)}
        resp = self.client.do_check_session_request(request_args=args)

        assert isinstance(resp, IdToken)
        assert _eq(resp.keys(), ['nonce', 'sub', 'aud', 'iss', 'exp', 'iat'])

    def test_do_end_session_request(self):
        self.client.redirect_uris = ["https://www.example.com/authz"]
        self.client.client_id = "a1b2c3"
        self.client.end_session_endpoint = "https://example.org/end_session"

        # RSA signing
        alg = "RS256"
        ktyp = alg2keytype(alg)
        _sign_key = self.client.keyjar.get_signing_key(ktyp)
        args = {"id_token": IDTOKEN.to_jwt(key=_sign_key, algorithm=alg),
                "redirect_url": "http://example.com/end"}

        resp = self.client.do_end_session_request(request_args=args,
                                                  state="state1")

        assert resp.status_code == 302
        assert resp.headers["location"].startswith("http://example.com/end")

    def test_do_registration_request(self):
        self.client.registration_endpoint = "https://example.org/registration"

        args = {"operation": "register",
                "application_type": "web",
                "application_name": "my service",
                "redirect_uri": "http://example.com/authz"}
        resp = self.client.do_registration_request(request_args=args)
        assert _eq(resp.keys(), ['redirect_uris', u'redirect_uri',
                                 'application_type', 'registration_client_uri',
                                 'client_secret_expires_at',
                                 'registration_access_token', 'client_id',
                                 'application_name', 'client_secret',
                                 'response_types'])

    def test_do_registration_response_missing_attribute(self):
        # this is lacking the required "redirect_uris" claim in the registration response
        msg = {
            "client_id": "s6BhdRkqt3",
            "client_secret": "ZJYCqe3GGRvdrudKyZS0XhGv_Z45DuKhCUk0gBR1vZk",
            "token_endpoint_auth_method": "client_secret_basic"
        }
        r = Response()
        r.status_code = 201
        r._content = str.encode(json.dumps(msg))

        with pytest.raises(RegistrationError) as ex:
            self.client.handle_registration_info(response=r)
            assert 'Missing required attribute \'redirect_uris\'' in str(ex.value)

    def test_do_user_info_request_with_access_token_refresh(self):
        args = {"response_type": ["code"],
                "scope": ["openid offline_access"],
                "prompt": "consent"}
        r = self.client.do_authorization_request(state="state0",
                                                 request_args=args)
        self.client.parse_response(AuthorizationResponse, r.headers["location"],
                                   sformat="urlencoded")
        self.client.do_access_token_request(scope="openid offline_access",
                                            state="state0")

        token = self.client.get_token(state="state0",
                                      scope="openid offline_access")
        token.token_expiration_time = utc_time_sans_frac() - 86400

        resp = self.client.do_user_info_request(state="state0")
        assert isinstance(resp, OpenIDSchema)
        assert _eq(resp.keys(), ['name', 'email', 'verified', 'nickname',
                                 'sub'])
        assert resp["name"] == "Melody Gardot"

    def test_openid_request_with_claims_request(self):
        claims = {
            "name": {"essential": True},
            "nickname": None,
            "email": {"essential": True},
            "verified": {"essential": True},
            "picture": None
        }

        areq = self.client.construct_AuthorizationRequest(
            request_args={
                "scope": "openid",
                "response_type": ["code"],
                "claims": ClaimsRequest(userinfo=Claims(**claims),
                                        id_token=Claims(auth_time=None,
                                                        acr={"values": ["2"]})),
                "max_age": 86400,
            },
            request_param="request")

        assert "request" in areq

    def test_openid_request_with_id_token_claims_request(self):
        areq = self.client.construct_AuthorizationRequest(
            request_args={"scope": "openid",
                          "response_type": ["code"],
                          "claims": {
                              "id_token": {"sub": {"value": "248289761001"}}}},
            request_param="request"
        )

        jwtreq = OpenIDRequest().deserialize(areq["request"], "jwt",
                                             keyjar=self.client.keyjar)
        assert _eq(jwtreq.keys(), ['claims',
                                   'redirect_uri', 'response_type',
                                   'client_id', 'scope'])

    def test_construct_UserInfoRequest_with_req_args(self):
        uir = self.client.construct_UserInfoRequest(
            request_args={"access_token": "access_token"})
        assert uir["access_token"] == "access_token"

    def test_construct_UserInfoRequest_2_with_token(self):
        self.client.grant["foo"] = Grant()
        self.client.grant["foo"].grant_expiration_time = time.time() + 60
        self.client.grant["foo"].code = "access_code"

        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access", id_token="IDTOKEN",
                                   scope=["openid"])

        self.client.grant["foo"].tokens.append(Token(resp))
        uir = self.client.construct_UserInfoRequest(state="foo",
                                                    scope=["openid"])
        assert uir["access_token"] == "access"

    def test_construct_CheckSessionRequest_with_req_args(self):
        csr = self.client.construct_CheckSessionRequest(
            request_args={"id_token": "id_token"})
        assert csr["id_token"] == "id_token"

    def test_construct_CheckSessionRequest_2(self):
        self.client.grant["foo"] = Grant()
        self.client.grant["foo"].grant_expiration_time = time.time() + 60
        self.client.grant["foo"].code = "access_code"

        resp = AccessTokenResponse(id_token="id_id_id_id",
                                   access_token="access", scope=["openid"])

        self.client.grant["foo"].tokens.append(Token(resp))

        csr = self.client.construct_CheckSessionRequest(state="foo",
                                                        scope=["openid"])
        assert csr["id_token"] == "id_id_id_id"

    def test_construct_RegistrationRequest(self):
        request_args = {
            "type": "client_associate",
            "client_id": CLIENT_ID,
            "contacts": ["foo@example.com"],
            "application_type": "web",
            "application_name": "EXAMPLE OIC service",
        }

        crr = self.client.construct_RegistrationRequest(
            request_args=request_args)
        assert _eq(crr.keys(), ['application_name', 'application_type', 'type',
                                'client_id', 'contacts', 'redirect_uris',
                                'response_types'])

    def test_construct_EndSessionRequest(self):
        self.client.grant["foo"] = Grant()
        self.client.grant["foo"].grant_expiration_time = time.time() + 60
        self.client.grant["foo"].code = "access_code"

        resp = AccessTokenResponse(id_token="id_id_id_id",
                                   access_token="access", scope=["openid"])

        self.client.grant["foo"].tokens.append(Token(resp))

        args = {"redirect_url": "http://example.com/end"}
        esr = self.client.construct_EndSessionRequest(state="foo",
                                                      request_args=args)
        assert _eq(esr.keys(), ['id_token', 'state', "redirect_url"])

    def test_construct_OpenIDRequest(self):
        self.client.scope = ["openid", "profile"]

        request_args = {"response_type": "code id_token",
                        "state": "af0ifjsldkj"}

        areq = self.client.construct_AuthorizationRequest(
            request_args=request_args)
        assert _eq(areq.keys(),
                   ['nonce', 'state', 'redirect_uri', 'response_type',
                    'client_id', 'scope'])

    def test_userinfo_request(self):
        aresp = AuthorizationResponse(code="code", state="state000")
        tresp = AccessTokenResponse(access_token="access_token",
                                    token_type="Bearer",
                                    expires_in=600, refresh_token="refresh",
                                    scope=["openid"])

        self.client.parse_response(AuthorizationResponse, aresp.to_urlencoded(),
                                   sformat="urlencoded", state="state0")
        self.client.parse_response(AccessTokenResponse, tresp.to_json(),
                                   state="state0")

        path, body, method, h_args = self.client.user_info_request(
            state="state0")
        assert path == "http://example.com/userinfo"
        assert method == "GET"
        assert body is None
        assert h_args == {'headers': {'Authorization': 'Bearer access_token'}}

    def test_userinfo_request_post(self):
        aresp = AuthorizationResponse(code="code", state="state000")
        tresp = AccessTokenResponse(access_token="access_token",
                                    token_type="bearer",
                                    expires_in=600, refresh_token="refresh",
                                    scope=["openid"])

        self.client.parse_response(AuthorizationResponse, aresp.to_urlencoded(),
                                   sformat="urlencoded", state="state0")
        self.client.parse_response(AccessTokenResponse, tresp.to_json(),
                                   state="state0")

        path, body, method, h_args = self.client.user_info_request(
            method="POST",
            state="state0")

        assert path == "http://example.com/userinfo"
        assert method == "POST"
        assert body == "access_token=access_token"
        assert h_args == {'headers': {
            'Content-Type': 'application/x-www-form-urlencoded'}}

    def test_sign_enc_request(self):
        KC_RSA_ENC = KeyBundle({"key": _key, "kty": "RSA", "use": "enc"})
        self.client.keyjar["test_provider"] = [KC_RSA_ENC]

        request_args = {"redirect_uri": self.redirect_uri,
                        "client_id": self.client.client_id,
                        "scope": "openid",
                        "response_type": "code"}

        kwargs = {"request_object_signing_alg": "none",
                  "request_object_encryption_alg": "RSA1_5",
                  "request_object_encryption_enc": "A128CBC-HS256",
                  "request_method": "parameter",
                  "target": "test_provider"}

        areq = self.client.construct_AuthorizationRequest(
            request_args=request_args,
            **kwargs)

        assert areq["request"]

    def test_verify_id_token_reject_wrong_aud(self, monkeypatch):
        issuer = "https://provider.example.com"
        monkeypatch.setattr(self.client, "provider_info", {"issuer": issuer})
        id_token = IdToken(**dict(iss=issuer, aud=["nobody"]))

        with pytest.raises(OtherError) as exc:
            self.client._verify_id_token(id_token)
        assert "me" in str(exc.value)

    def test_verify_id_token_reject_wrong_azp(self, monkeypatch):
        issuer = "https://provider.example.com"
        monkeypatch.setattr(self.client, "provider_info", {"issuer": issuer})
        id_token = IdToken(
            **dict(iss=issuer,
                   aud=["nobody", "somebody", self.client.client_id],
                   azp="nobody"))

        with pytest.raises(OtherError) as exc:
            self.client._verify_id_token(id_token)
        assert "me" in str(exc.value)

    def test_clean_tokens_fresh(self):
        self.client.grant["foo"] = Grant()
        self.client.grant["foo"].grant_expiration_time = time.time() + 60
        self.client.grant["foo"].code = "access_code"

        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access", id_token="IDTOKEN",
                                   scope=["openid"])

        self.client.grant["foo"].tokens.append(Token(resp))
        self.client.clean_tokens()
        assert len(self.client.grant["foo"].tokens) == 1

    def test_clean_tokens_replaced(self):
        self.client.grant["foo"] = Grant()
        self.client.grant["foo"].grant_expiration_time = time.time() + 60
        self.client.grant["foo"].code = "access_code"

        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access", id_token="IDTOKEN",
                                   scope=["openid"])

        self.client.grant["foo"].tokens.append(Token(resp))
        self.client.grant["foo"].tokens[0].replaced = True
        self.client.clean_tokens()
        assert len(self.client.grant["foo"].tokens) == 0

    def test_clean_tokens_stale(self):
        self.client.grant["foo"] = Grant()
        self.client.grant["foo"].grant_expiration_time = time.time() + 60
        self.client.grant["foo"].code = "access_code"

        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access", id_token="IDTOKEN",
                                   scope=["openid"])

        self.client.grant["foo"].tokens.append(Token(resp))
        self.client.grant["foo"].tokens[0].token_expiration_time = 10
        self.client.clean_tokens()
        assert len(self.client.grant["foo"].tokens) == 0


class TestServer(object):
    @pytest.fixture(autouse=True)
    def create_server(self):
        self.srv = Server()
        self.srv.keyjar = KEYJ

    def test_parse_authz_req(self):
        ar = AuthorizationRequest(response_type=["code"], client_id="foobar",
                                  redirect_uri="http://foobar.example.com/oaclient",
                                  state="cold", nonce="NONCE", scope=["openid"])

        # query string
        uencq = ar.to_urlencoded()
        areq = self.srv.parse_authorization_request(query=uencq)

        assert isinstance(areq, AuthorizationRequest)
        assert areq["response_type"] == ["code"]
        assert areq["client_id"] == "foobar"
        assert areq["redirect_uri"] == "http://foobar.example.com/oaclient"
        assert areq["state"] == "cold"

        # urlencoded
        urluenc = "https://example.com/authz?{}".format(uencq)
        areq = self.srv.parse_authorization_request(url=urluenc)

        assert isinstance(areq, AuthorizationRequest)
        assert areq["response_type"] == ["code"]
        assert areq["client_id"] == "foobar"
        assert areq["redirect_uri"] == "http://foobar.example.com/oaclient"
        assert areq["state"] == "cold"

    def test_parse_authz_req_jwt(self):
        ar = AuthorizationRequest(response_type=["code"], client_id=CLIENT_ID,
                                  redirect_uri="http://foobar.example.com/oaclient",
                                  state="cold", nonce="NONCE", scope=["openid"])

        _keys = self.srv.keyjar.get_verify_key(owner=CLIENT_ID)
        _jwt = ar.to_jwt(key=_keys, algorithm="HS256")

        req = self.srv.parse_jwt_request(txt=_jwt)

        assert isinstance(req, AuthorizationRequest)
        assert req["response_type"] == ["code"]
        assert req["client_id"] == CLIENT_ID
        assert req["redirect_uri"] == "http://foobar.example.com/oaclient"
        assert req["state"] == "cold"

    def test_server_parse_token_request(self):
        atr = AccessTokenRequest(grant_type="authorization_code",
                                 code="SplxlOBeZQQYbYS6WxSbIA",
                                 redirect_uri="https://client.example.com/cb",
                                 client_id=CLIENT_ID, extra="foo")

        uenc = atr.to_urlencoded()

        tr = self.srv.parse_token_request(body=uenc)

        assert isinstance(tr, AccessTokenRequest)
        assert _eq(tr.keys(),
                   ['code', 'redirect_uri', 'grant_type', 'client_id',
                    'extra'])
        assert tr["grant_type"] == "authorization_code"
        assert tr["code"] == "SplxlOBeZQQYbYS6WxSbIA"
        assert tr["extra"] == "foo"

    def test_server_parse_refresh_token_request(self):
        ratr = RefreshAccessTokenRequest(refresh_token="ababababab",
                                         client_id="Client_id")
        uenc = ratr.to_urlencoded()
        tr = self.srv.parse_refresh_token_request(body=uenc)

        assert isinstance(tr, RefreshAccessTokenRequest)
        assert tr["refresh_token"] == "ababababab"
        assert tr["client_id"] == "Client_id"

    def test_parse_urlencoded(self):
        loc = "http://example.com/userinfo?access_token=access_token"
        qdict = self.srv._parse_urlencoded(loc)
        assert qdict["access_token"] == ["access_token"]

    def test_parse_authorization_request(self):
        areq = AuthorizationRequest(response_type="code", client_id="client_id",
                                    redirect_uri="http://example.com/authz",
                                    scope=["openid"], state="state0",
                                    nonce="N0nce")
        qdict = self.srv.parse_authorization_request(query=areq.to_urlencoded())
        assert _eq(qdict.keys(), ['nonce', 'state', 'redirect_uri',
                                  'response_type', 'client_id', 'scope'])
        assert qdict["state"] == "state0"

    def test_parse_token_request(self):
        treq = AccessTokenRequest(code="code",
                                  redirect_uri="http://example.com/authz",
                                  client_id=CLIENT_ID,
                                  grant_type='authorization_code')
        qdict = self.srv.parse_token_request(body=treq.to_urlencoded())
        assert isinstance(qdict, AccessTokenRequest)
        assert _eq(qdict.keys(), ['code', 'redirect_uri', 'client_id',
                                  'grant_type'])
        assert qdict["client_id"] == CLIENT_ID
        assert qdict["code"] == "code"

    def test_parse_userinfo_requesr(self):
        uireq = UserInfoRequest(access_token="access_token")
        uencq = uireq.to_urlencoded()

        qdict = self.srv.parse_user_info_request(data=uencq)
        assert _eq(qdict.keys(), ['access_token'])
        assert qdict["access_token"] == "access_token"

        url = "https://example.org/userinfo?{}".format(uencq)
        qdict = self.srv.parse_user_info_request(data=url)
        assert _eq(qdict.keys(), ['access_token'])
        assert qdict["access_token"] == "access_token"

    def test_parse_registration_request(self):
        regreq = RegistrationRequest(contacts=["roland.hedberg@adm.umu.se"],
                                     redirect_uris=[
                                         "http://example.org/jqauthz"],
                                     application_name="pacubar",
                                     client_id=CLIENT_ID,
                                     operation="register",
                                     application_type="web")

        request = self.srv.parse_registration_request(
            data=regreq.to_urlencoded())
        assert isinstance(request, RegistrationRequest)
        assert _eq(request.keys(), ['redirect_uris', 'contacts', 'client_id',
                                    'application_name', 'operation',
                                    'application_type', 'response_types'])
        assert request["application_name"] == "pacubar"
        assert request["operation"] == "register"

    def test_parse_refresh_session_request(self):
        rsreq = RefreshSessionRequest(id_token="id_token",
                                      redirect_url="http://example.com/authz",
                                      state="state0")
        uencq = rsreq.to_urlencoded()

        request = self.srv.parse_refresh_session_request(query=uencq)
        assert isinstance(request, RefreshSessionRequest)
        assert _eq(request.keys(), ['id_token', 'state', 'redirect_url'])
        assert request["id_token"] == "id_token"

        url = "https://example.org/userinfo?{}".format(uencq)
        request = self.srv.parse_refresh_session_request(url=url)
        assert isinstance(request, RefreshSessionRequest)
        assert _eq(request.keys(), ['id_token', 'state', 'redirect_url'])
        assert request["id_token"] == "id_token"

    def test_parse_check_session_request(self):
        csreq = CheckSessionRequest(
            id_token=IDTOKEN.to_jwt(key=KC_SYM_S.get(alg2keytype("HS256")),
                                    algorithm="HS256"))
        request = self.srv.parse_check_session_request(
            query=csreq.to_urlencoded())
        assert isinstance(request, IdToken)
        assert _eq(request.keys(), ['nonce', 'sub', 'aud', 'iss', 'exp', 'iat'])
        assert request["aud"] == ["client_1"]

    def test_parse_end_session_request(self):
        esreq = EndSessionRequest(
            id_token=IDTOKEN.to_jwt(key=KC_SYM_S.get(alg2keytype("HS256")),
                                    algorithm="HS256"),
            redirect_url="http://example.org/jqauthz",
            state="state0")

        request = self.srv.parse_end_session_request(
            query=esreq.to_urlencoded())
        assert isinstance(request, EndSessionRequest)
        assert _eq(request.keys(), ['id_token', 'redirect_url', 'state'])
        assert request["state"] == "state0"

        assert request["id_token"]["aud"] == ["client_1"]

    def test_parse_open_id_request(self):
        userinfo_claims = Claims(name={"essential": True}, nickname=None,
                                 email={"essential": True},
                                 email_verified={"essential": True},
                                 picture=None)
        id_token_claims = Claims(auth_time={"essential": True,
                                            "acr": {"values": [
                                                "urn:mace:incommon:iap:silver"]}})
        claims_req = ClaimsRequest(userinfo=userinfo_claims,
                                   id_token=id_token_claims)

        oidreq = OpenIDRequest(response_type=["code", "id_token"],
                               client_id=CLIENT_ID,
                               redirect_uri="https://client.example.com/cb",
                               scope="openid profile", state="n-0S6_WzA2Mj",
                               nonce="af0ifjsldkj", max_age=86400,
                               claims=claims_req)

        request = self.srv.parse_open_id_request(data=oidreq.to_json(),
                                                 sformat="json")
        assert isinstance(request, OpenIDRequest)
        assert _eq(request.keys(), ['nonce', 'claims', 'state', 'redirect_uri',
                                    'response_type', 'client_id', 'scope',
                                    'max_age'])
        assert request["nonce"] == "af0ifjsldkj"
        assert "email" in request["claims"]["userinfo"]

    def test_make_id_token(self):
        self.srv.keyjar["http://oic.example/idp"] = KC_RSA

        session = {"sub": "user0",
                   "client_id": "http://oic.example/rp"}
        issuer = "http://oic.example/idp"
        code = "abcdefghijklmnop"
        _idt = self.srv.make_id_token(session, loa="2", issuer=issuer,
                                      code=code, access_token="access_token")

        algo = "RS256"
        ckey = self.srv.keyjar.get_signing_key(alg2keytype(algo),
                                               issuer)
        _signed_jwt = _idt.to_jwt(key=ckey, algorithm="RS256")

        idt = IdToken().from_jwt(_signed_jwt, keyjar=self.srv.keyjar)
        _jwt = JWT().unpack(_signed_jwt)

        lha = left_hash(code.encode("utf-8"),
                        func="HS" + _jwt.headers["alg"][-3:])
        assert lha == idt["c_hash"]

        atr = AccessTokenResponse(id_token=_signed_jwt,
                                  access_token="access_token",
                                  token_type="Bearer")
        atr["code"] = code
        assert atr.verify(keyjar=self.srv.keyjar)


class TestScope2Claims(object):
    def test_scope2claims(self):
        claims = scope2claims(['profile', 'email'])
        assert Counter(claims.keys()) == Counter(
            SCOPE2CLAIMS['profile'] + SCOPE2CLAIMS['email'])

    def test_scope2claims_with_non_standard_scope(self):
        claims = scope2claims(['my_scope', 'email'])
        assert Counter(claims.keys()) == Counter(SCOPE2CLAIMS['email'])

    def test_scope2claims_extra_scope_dict(self):
        claims = scope2claims(['my_scope', 'email'], extra_scope_dict={'my_scope': ['my_attribute']})
        assert sorted(claims.keys()) == ['email', 'email_verified', 'my_attribute']


def test_request_attr_mis_match():
    redirect_uri = "http://example.com/redirect"
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)
    client.redirect_uris = [redirect_uri]
    client.authorization_endpoint = "http://example.com/authorization"
    client.client_secret = "abcdefghijklmnop"
    client.keyjar[""] = KC_RSA
    client.behaviour = {
        "request_object_signing_alg": DEF_SIGN_ALG["openid_request_object"]}

    srv = Server()
    srv.keyjar = KEYJ

    areq = client.construct_AuthorizationRequest(
        request_args={
            "scope": "openid",
            "response_type": ["code"],
            "max_age": 86400,
            'state': 'foobar'
        },
        request_param="request")

    for attr in ['state', 'max_age', 'client_id']:
        del areq[attr]

    areq.lax = True
    req = srv.parse_authorization_request(query=areq.to_urlencoded())

    assert req.verify()


def test_request_1():
    srv = Server()
    srv.keyjar = KEYJ

    areq = 'redirect_uri=https%3A%2F%2Fnode-openid-client.dev%2Fcb&request' \
           '=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0' \
           '.eyJzdGF0ZSI6ImZvb2JhciIsImlzcyI6Inp2bWk4UGdJbURiOSIsImF1ZCI6I' \
           'mh0dHBzOi8vcnAuY2VydGlmaWNhdGlvbi5vcGVuaWQubmV0OjgwODAvbm9kZS1' \
           'vcGVuaWQtY2xpZW50L3JwLXJlcXVlc3RfdXJpLXVuc2lnbmVkIiwiY2xpZW50X' \
           '2lkIjoienZtaThQZ0ltRGI5In0.&client_id=zvmi8PgImDb9&scope=openid' \
           '&response_type=code'

    req = srv.parse_authorization_request(query=areq)

    assert req


def test_request_duplicate_state():
    srv = Server()
    srv.keyjar = KEYJ

    areq = 'redirect_uri=https%3A%2F%2Fnode-openid-client.dev%2Fcb&state=barf' \
           '&request' \
           '=eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0' \
           '.eyJzdGF0ZSI6ImZvb2JhciIsImlzcyI6Inp2bWk4UGdJbURiOSIsImF1ZCI6Imh0dHBzOi8v' \
           'cnAuY2VydGlmaWNhdGlvbi5vcGVuaWQubmV0OjgwODAvbm9kZS1vcGVuaWQtY2xpZW50L3JwL' \
           'XJlcXVlc3RfdXJpLXVuc2lnbmVkIiwiY2xpZW50X2lkIjoienZtaThQZ0ltRGI5In0.&' \
           'client_id=zvmi8PgImDb9&scope=openid&response_type=code'

    req = srv.parse_authorization_request(query=areq)

    assert req['state'] == 'foobar'
    assert req['redirect_uri'] == 'https://node-openid-client.dev/cb'


def test_do_userinfo_request_no_state_or_token():
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)

    method = "GET"
    state = ""
    scope = "openid"
    request = "openid"
    kwargs = {"request": request,
              "userinfo_endpoint": 'http://example.com/userinfo'}

    path, body, method, h_args = client.user_info_request(method, state,
                                                          scope, **kwargs)

    assert path == 'http://example.com/userinfo'
    assert h_args == {}
    assert body is None
    assert method == 'GET'


def test_do_userinfo_request_token_no_state():
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)

    method = "GET"
    state = ""
    scope = "openid"
    request = "openid"
    kwargs = {"request": request,
              "userinfo_endpoint": 'http://example.com/userinfo',
              "token": "abcdefgh"}

    path, body, method, h_args = client.user_info_request(method, state,
                                                          scope, **kwargs)

    assert path == 'http://example.com/userinfo'
    assert h_args == {'headers': {'Authorization': 'Bearer abcdefgh'}}
    assert method == 'GET'
    assert body is None


def test_do_userinfo_request_explicit_token_none():
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)

    method = "GET"
    state = ""
    scope = "openid"
    request = "openid"
    kwargs = {"request": request,
              "userinfo_endpoint": 'http://example.com/userinfo',
              "token": None}

    path, body, method, h_args = client.user_info_request(method, state,
                                                          scope, **kwargs)

    assert path == 'http://example.com/userinfo'
    assert h_args == {}
    assert method == 'GET'
    assert body is None


def test_do_userinfo_request_with_state():
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)
    client.grant['foxhound'] = Grant()
    resp = AccessTokenResponse(access_token="access", token_type="Bearer")
    _token = Token(resp)
    client.grant["foxhound"].tokens = [_token]

    method = "GET"
    state = "foxhound"
    scope = "openid"
    request = "openid"
    kwargs = {"request": request,
              "userinfo_endpoint": 'http://example.com/userinfo'}

    path, body, method, h_args = client.user_info_request(method, state,
                                                          scope, **kwargs)

    assert path == 'http://example.com/userinfo'
    assert h_args == {'headers': {'Authorization': 'Bearer access'}}
    assert method == 'GET'
    assert body is None


def token_callback(endp):
    return 'abcdef'


def fake_request(*args, **kwargs):
    r = Response()
    r.status_code = 200

    try:
        _token = kwargs['headers']['Authorization']
    except KeyError:
        r._content = b'{"shoe_size": 10}'
    else:
        _token = _token[7:]
        if _token == 'abcdef':
            r._content = b'{"shoe_size": 11}'
        else:
            r._content = b'{"shoe_size": 12}'

    r.headers = {'content-type': 'application/json'}
    return r


def test_fetch_distributed_claims_with_callback():
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)

    client.http_request = fake_request
    userinfo = {
        'sub': 'foobar',
        '_claim_names': {'shoe_size': 'src1'},
        '_claim_sources': {
            "src1": {
                "endpoint": "https://bank.example.com/claim_source"}}
    }

    _ui = client.fetch_distributed_claims(userinfo, token_callback)

    assert _ui['shoe_size'] == 11
    assert _ui['sub'] == 'foobar'
    assert '_claim_names' not in _ui
    assert '_claim_sources' not in _ui


def test_fetch_distributed_claims_with_no_callback():
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)

    client.http_request = fake_request
    userinfo = {
        'sub': 'foobar',
        '_claim_names': {'shoe_size': 'src1'},
        '_claim_sources': {
            "src1": {
                "endpoint": "https://bank.example.com/claim_source"}}
    }

    _ui = client.fetch_distributed_claims(userinfo, callback=None)

    assert _ui['shoe_size'] == 10
    assert _ui['sub'] == 'foobar'


def test_fetch_distributed_claims_with_explicit_no_token():
    client = Client(CLIENT_ID, client_authn_method=CLIENT_AUTHN_METHOD)

    client.http_request = fake_request
    userinfo = {
        'sub': 'foobar',
        '_claim_names': {'shoe_size': 'src1'},
        '_claim_sources': {
            "src1": {
                "access_token": None,
                "endpoint": "https://bank.example.com/claim_source"}}
    }

    _ui = client.fetch_distributed_claims(userinfo, callback=None)

    assert _ui['shoe_size'] == 10
    assert _ui['sub'] == 'foobar'
