#!/usr/bin/env python
#from oic.oauth2 import KeyStore

__author__ = 'rohe0002'

import time

from oic.oic import Grant
from oic.oic import Token
from oic.oic import Client
from oic.oic import Server
from oic.oic.message import *

from oic.oauth2.message import SCHEMA as OA2_SCHEMA
from oic.oauth2.message import GrantExpired, message_from_schema
from oic.oauth2.message import MissingRequiredAttribute

from oic.utils import time_util
from oic.utils.time_util import time_sans_frac

from pytest import raises

from tests.fakeoicsrv import MyFakeOICServer

def _eq(l1, l2):
    return set(l1) == set(l2)

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KEYS = [
    ["abcdefghijklmnop", "hmac", "verify", "client_1"],
    ["abcdefghijklmnop", "hmac", "sign", "client_1"]
]

SIGN_KEY = {"hmac": ["abcdefghijklmnop"]}

IDTOKEN = message("IdToken", iss="http://oic.example.org/", user_id="user_id",
                  aud=CLIENT_ID, exp=time_sans_frac()+86400, nonce="N0nce")

# ----------------- CLIENT --------------------

class TestOICClient():
    def setup_class(self):
        self.client = Client(CLIENT_ID)
        self.client.redirect_uris = ["http://example.com/redirect"]
        self.client.client_secret = CLIENT_SECRET

    def test_areq_1(self):
        ar = self.client.construct_AuthorizationRequest(
            request_args={"response_type":["code"]})

        print ar.to_dict()
        assert ar["redirect_uri"] == "http://example.com/redirect"
        assert ar["response_type"] == ["code"]
        assert "state" not in ar
        assert "scope" not in ar

    def test_areq_2(self):
        self.client.state = "abc"
        req_args = {"response_type":["code"], "scope": ["foo", "bar"]}
        ar = self.client.construct_AuthorizationRequest(request_args=req_args)

        assert ar["redirect_uri"] == "http://example.com/redirect"
        assert ar["response_type"] == ["code"]
        assert ar["client_id"] == CLIENT_ID
        assert ar["state"] == "abc"
        assert ar["scope"] == ["foo", "bar"]

    def test_areq_replace_default_state(self):
        self.client.state = "efg"
        req_args = {"response_type":["code"], "scope": ["foo", "bar"]}
        ar = self.client.construct_AuthorizationRequest(request_args=req_args)

        assert ar["redirect_uri"] == "http://example.com/redirect"
        assert ar["response_type"] == ["code"]
        assert ar["client_id"] == CLIENT_ID
        assert ar["state"] == "efg"
        assert ar["scope"] == ["foo", "bar"]

    def test_parse_authz_resp_url(self):
        url = "https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=ghi"
        aresp = self.client.parse_response(SCHEMA["AuthorizationResponse"],
                                           info=url, format="urlencoded")

        assert aresp["code"] == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp["state"] == "ghi"

        assert self.client.grant["ghi"]
        assert self.client.grant["ghi"].code == aresp["code"]
        assert self.client.grant["ghi"].grant_expiration_time

    def test_parse_authz_resp_query(self):
        query = "code=SplxlOBeZQQYbYS6WxSbIA&state=hij"
        aresp = self.client.parse_response(SCHEMA["AuthorizationResponse"],
                                           info=query, format="urlencoded")

        assert aresp["code"] == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp["state"] == "hij"

        print self.client.grant.keys()
        assert self.client.grant["hij"]
        assert self.client.grant["hij"].code == aresp["code"]
        assert self.client.grant["hij"].grant_expiration_time

    def test_parse_authz_resp_query_multi_scope(self):
        query = "code=SplxlOBeZQQYbYS6WxAAAA&state=klm"
        aresp = self.client.parse_response(SCHEMA["AuthorizationResponse"],
                                           info=query, format="urlencoded")

        assert aresp["code"] == "SplxlOBeZQQYbYS6WxAAAA"
        assert aresp["state"] == "klm"

        assert self.client.grant["klm"]
        assert self.client.grant["klm"].code == aresp["code"]
        assert self.client.grant["klm"].grant_expiration_time

        assert _eq(self.client.grant.keys(), ['ghi', 'hij', 'klm'])

    def test_parse_authz_resp_query_unknown_parameter(self):
        query = "code=SplxlOBeZQQYbYS6WxSbIA&state=xyz&foo=bar"
        aresp = self.client.parse_response(SCHEMA["AuthorizationResponse"],
                                           info=query, format="urlencoded")

        assert aresp["code"] == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp["state"] == "xyz"

        print aresp.__dict__.keys()
        assert "foo" not in aresp.__dict__

        assert self.client.grant["xyz"]
        assert self.client.grant["xyz"].code == aresp["code"]
        assert self.client.grant["xyz"].grant_expiration_time

    def test_get_access_token_request_1(self):
        self.client.reset()
        self.client.redirect_uris = ["http://client.example.com/authz"]
        grant = Grant()
        grant.code = "AbCdEf"
        grant.grant_expiration_time = time_util.time_sans_frac() + 30
        self.client.grant = {"stat": grant}

        # scope is default=""
        atr = self.client.construct_AccessTokenRequest(state="stat")

        assert atr["grant_type"] == "authorization_code"
        assert atr["code"] == "AbCdEf"
        assert atr["redirect_uri"] == "http://client.example.com/authz"

    def test_construct_access_token_request_fail(self):
        raises(Exception,
               'self.client.construct_AccessTokenRequest(state="unknown")')

    def test_get_access_token_request_override(self):
        self.client.reset()
        self.client.redirect_uris = ["http://client.example.com/authz"]
        grant = Grant()
        grant.code = "AbCdEf"
        grant.grant_expiration_time = time_util.time_sans_frac() + 30
        self.client.grant = {"xyz": grant}

        atr = self.client.construct_AccessTokenRequest(state="xyz")

        assert atr["grant_type"] == "authorization_code"
        assert atr["code"] == "AbCdEf"
        assert atr["redirect_uri"] == "http://client.example.com/authz"

    def test_construct_request_no_input(self):
        self.client.response_type = ["code"]
        atr = self.client.construct_AuthorizationRequest()

        print atr
        assert atr["redirect_uri"] == "http://client.example.com/authz"
        assert atr["response_type"] == ["code"]
        assert atr["client_id"] == CLIENT_ID

    def test_parse_access_token_response(self):
        jso = """{
       "access_token":"2YotnFZFEjr1zCsicMWpAA",
       "token_type":"example",
       "expires_in":3600,
       "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
       "example_parameter":"example_value"
     }"""

        self.client.parse_response(SCHEMA["AccessTokenResponse"],
                                   info="".join([
                                   x.strip() for x in jso.split("\n")]))

        assert self.client.grant
        _grant = self.client.grant[""]
        assert len(_grant.tokens) == 1
        token = _grant.tokens[0]
        assert token.access_token == "2YotnFZFEjr1zCsicMWpAA"
        assert token.token_type == "example"
        assert token.expires_in == 3600
        assert token.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"

        # I'm dropping parameters I don't recognize
        assert "example_parameter" not in self.client.__dict__

        #assert self.client.access_token_is_valid()

    def test_get_access_token_refresh_1(self):
        print self.client.grant

        self.client.grant[""].grant_expiration_time = time.time()+60
        self.client.grant[""].code = "access_code"
        token = self.client.grant[""].tokens[0]
        print token
        # Uses refresh_token from previous response
        atr = self.client.construct_RefreshAccessTokenRequest(token=token)

        assert atr.type() == "RefreshAccessTokenRequest"
        assert atr["grant_type"] == "refresh_token"
        assert atr["refresh_token"] == "tGzv3JOkF0XG5Qx2TlKWIA"

    def test_get_access_token_refresh_2(self):
        self.client.grant["foo"] = Grant()
        self.client.grant["foo"].grant_expiration_time = time.time()+60
        self.client.grant["foo"].code = "access_code"

        print self.client.grant["foo"]
        resp = message("AccessTokenResponse")
        resp["refresh_token"] = "refresh_with_me"
        resp["access_token"] = "access"
        self.client.grant["foo"].tokens.append(Token(resp))
        # Uses refresh_token from previous response
        atr = self.client.construct_RefreshAccessTokenRequest(state="foo")

        assert atr.type() == "RefreshAccessTokenRequest"
        assert atr["grant_type"] == "refresh_token"
        assert atr["refresh_token"] == "refresh_with_me"

    def test_parse_authz_err_response(self):
        ruri = "https://client.example.com/cb?error=access_denied&amp;state=xyz"

        resp = self.client.parse_response(SCHEMA["AuthorizationResponse"],
                                          info=ruri, format="urlencoded")

        print type(resp), resp
        assert resp.type() == "AuthorizationErrorResponse"

        assert resp["error"] == "access_denied"
        assert resp["state"] == "xyz"

    def test_return_non_existant_grant(self):
        assert self.client.grant_from_state("123456abcdef") is None

    def test_construct_request_with_extra_args(self):
        req = self.client.construct_AccessTokenRequest(state="foo",
                                                       extra_args={"foo":"bar"})

        assert req
        print req.keys()
        assert _eq(req.keys(), ['code', 'grant_type', 'client_id',
                                'client_secret', 'redirect_uri', 'foo'])
        assert req["foo"] == "bar"

    def test_construct_TokenRevocationRequest(self):
        req = self.client.construct_TokenRevocationRequest(state="foo")

        assert req
        print req.keys()
        assert _eq(req.keys(), ['token'])
        assert req["token"] == "access"

    def test_request_info_simple(self):
        self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(
                                                SCHEMA["AuthorizationRequest"])

        # default == "POST"
        assert uri == 'https://example.com/authz'
        areq = message("AuthorizationRequest").from_urlencoded(body)
        assert _eq(areq.keys(), ["nonce","redirect_uri","response_type",
                                 "client_id"])
        assert h_args == {'headers': {'content-type': 'application/x-www-form-urlencoded'}}
        assert cis.type() == "AuthorizationRequest"

    def test_request_info_simple_get(self):
        uri, body, h_args, cis = self.client.request_info(
                                SCHEMA["AuthorizationRequest"], method="GET")

        (url, query) = uri.split("?")
        areq = message("AuthorizationRequest").from_urlencoded(query)
        assert _eq(areq.keys(), ["nonce","redirect_uri","response_type",
                                 "client_id"])
        assert areq["redirect_uri"] == "http://client.example.com/authz"

        assert body is None
        assert h_args == {}
        assert cis.type() == "AuthorizationRequest"

    def test_request_info_simple_get_with_req_args(self):
        #self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(
                                SCHEMA["AuthorizationRequest"], method="GET",
                                request_args={"state":"init"})

        print uri
        (url, query) = uri.split("?")
        areq = message("AuthorizationRequest").from_urlencoded(query)
        assert _eq(areq.keys(), ["nonce","redirect_uri","response_type",
                                 "client_id", "state"])
        assert areq["state"]
        assert body is None
        assert h_args == {}
        assert cis.type() == "AuthorizationRequest"

    def test_request_info_simple_get_with_extra_args(self):
        #self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(
                                    SCHEMA["AuthorizationRequest"],
                                    method="GET", extra_args={"rock":"little"})

        print uri
        (url, query) = uri.split("?")
        areq = message("AuthorizationRequest").from_urlencoded(query)
        assert _eq(areq.keys(), ["nonce","redirect_uri","response_type",
                                 "client_id", "rock"])
        assert body is None
        assert h_args == {}
        assert cis.type() == "AuthorizationRequest"

    def test_request_info_with_req_and_extra_args(self):
        #self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(
                    SCHEMA["AuthorizationRequest"], method="GET",
                    request_args={"state":"init"},
                    extra_args={"rock":"little"})

        print uri
        (url, query) = uri.split("?")
        areq = message("AuthorizationRequest").from_urlencoded(query)
        assert _eq(areq.keys(), ["nonce","redirect_uri","response_type",
                                 "client_id", "state", "rock"])
        assert body is None
        assert h_args == {}
        assert cis.type() == "AuthorizationRequest"

    def test_do_authorization_request(self):
        self.client.grant = {}
        self.client.redirect_uris = ["https://www.example.com/authz"]
        self.client.authorization_endpoint = "http://oic.example.org/authorization"
        self.client.client_id = "a1b2c3"
        self.client.state = "state0"
        self.client.http = MyFakeOICServer(KEYS)

        args = {"response_type":["code"],
                "scope": ["openid"]}
        result = self.client.do_authorization_request(state=self.client.state,
                                                      request_args=args)
        assert result.status == 302
        assert result.location.startswith(self.client.redirect_uris[0])
        _, query = result.location.split("?")

        self.client.parse_response(SCHEMA["AuthorizationResponse"], info=query,
                                   format="urlencoded")

    def test_access_token_request(self):
        self.client.token_endpoint = "http://oic.example.org/token"

        print self.client.grant.keys()
        print self.client.state
        print self.client.grant[self.client.state]

        resp = self.client.do_access_token_request(scope="openid")
        print resp
        print resp.keys()
        assert resp.type() == "AccessTokenResponse"
        assert _eq(resp.keys(), ['token_type', 'state', 'access_token',
                                 'expires_in', 'refresh_token', 'scope'])

    def test_do_user_info_request(self):
        self.client.userinfo_endpoint = "http://oic.example.org/userinfo"

        resp = self.client.do_user_info_request(state=self.client.state)
        assert resp.type() == "OpenIDSchema"
        assert _eq(resp.keys(), ['name', 'email', 'verified', 'nickname'])
        assert resp["name"] == "Melody Gardot"

    def test_do_access_token_refresh(self):
        #token = self.client.get_token(scope="openid")

        resp = self.client.do_access_token_refresh(scope="openid")
        print resp
        assert resp.type() == "AccessTokenResponse"
        assert _eq(resp.keys(), ['token_type', 'state', 'access_token',
                                 'expires_in', 'refresh_token', 'scope'])

    def test_do_check_session_request(self):
        self.client.redirect_uris = ["https://www.example.com/authz"]
        self.client.client_id = CLIENT_ID
        self.client.check_session_endpoint = "https://example.org/check_session"

        print self.client.keystore._store
        _sign_key = self.client.keystore.get_sign_key()
        print _sign_key
        args = {"id_token": IDTOKEN.to_jwt(key=_sign_key)}
        resp = self.client.do_check_session_request(request_args=args)

        assert resp.type() == "IdToken"
        assert _eq(resp.keys(), ['nonce', 'user_id', 'aud', 'iss', 'exp'])

    def test_do_end_session_request(self):
        self.client.redirect_uris = ["https://www.example.com/authz"]
        self.client.client_id = "a1b2c3"
        self.client.end_session_endpoint = "https://example.org/end_session"

        _sign_key = self.client.keystore.get_sign_key()
        args = {"id_token": IDTOKEN.to_jwt(key=_sign_key),
                "redirect_url": "http://example.com/end"}

        resp = self.client.do_end_session_request(request_args=args,
                                                  state="state1")

        assert resp["status"] == 302
        assert resp["location"].startswith("http://example.com/end")

    def test_do_registration_request(self):
        self.client.registration_endpoint = "https://example.org/registration"

        args = {"type":"client_associate",
                "application_type": "web",
                "application_name": "my service",
                "redirect_uri": "http://example.com/authz"}
        resp = self.client.do_registration_request(request_args=args)
        print resp
        assert _eq(resp.keys(),['client_secret', 'expires_at', 'client_id'])

    def test_do_user_info_request_with_access_token_refresh(self):
        self.client.userinfo_endpoint = "http://oic.example.org/userinfo"

        token = self.client.get_token(state=self.client.state, scope="openid")
        token.token_expiration_time = time_sans_frac()-86400

        resp = self.client.do_user_info_request(state=self.client.state)
        assert resp.type() == "OpenIDSchema"
        assert _eq(resp.keys(), ['name', 'email', 'verified', 'nickname'])
        assert resp["name"] == "Melody Gardot"

    def test_openid_request_with_request_1(self):
        claims = {
            "name": None,
            "nickname": {"optional": True},
            "email": None,
            "verified": None,
            "picture": {"optional": True}
        }

        areq = self.client.construct_OpenIDRequest(
            userinfo_claims={"claims":claims,
                             "preferred_locale":"en"},
            idtoken_claims={"claims":{"auth_time": None,
                                      "acr":{"values":["2"]}},
                            "max_age": 86400},
            )

        print areq
        assert areq
        assert "request" in areq

    def test_openid_request_with_request_2(self):
        areq = self.client.construct_OpenIDRequest(
            idtoken_claims={"claims": {"user_id": {"value":"248289761001"}}},
        )

        print areq
        assert areq
        assert areq.request

        _keys = self.client.keystore.get_keys("verify", owner=None)
        jwtreq = msg_deser(areq["request"], "jwt", "OpenIDRequest", key=_keys)
        print
        print jwtreq
        print jwtreq.keys()
        assert _eq(jwtreq.keys(), ['nonce', 'id_token', 'state',
                                   'redirect_uri', 'response_type',
                                   'client_id'])

def test_get_authorization_request():
    client = Client()
    client.redirect_uris = ["https://www.example.com/authz"]
    client.client_id = "a1b2c3"
    args = {"response_type":["code"]}
    ar = client.construct_AuthorizationRequest(request_args=args)
    assert ar["client_id"] == 'a1b2c3'
    assert ar["redirect_uri"] == 'https://www.example.com/authz'
    assert ar["response_type"] == ['code']

    client = Client()
    client.client_id = "a1b2c3"
    args = {"response_type":["code"],
            "redirect_uri": "https://www.example.com/authz"}
    ar = client.construct_AuthorizationRequest(request_args=args)
    assert ar["client_id"] == 'a1b2c3'
    assert ar["redirect_uri"] == 'https://www.example.com/authz'
    assert ar["response_type"] == ['code']

def test_get_access_token_request():
    resp = message("AuthorizationResponse", code="code", state="state")

    grant = Grant(1)
    grant.add_code(resp)

    client = Client()
    client.grant["openid"] = grant
    time.sleep(2)
    raises(GrantExpired,
           'client.construct_AccessTokenRequest(state="openid")')


def test_parse_access_token_response():
    client = Client()

    at = message("AccessTokenResponse", access_token="SlAV32hkKG",
                 token_type="Bearer", refresh_token="8xLOxBtZp8",
                 expires_in=3600)

    atj = at.to_json()

    ATR = SCHEMA["AccessTokenResponse"]
    atr = client.parse_response(ATR, info=atj)

    assert _eq(atr.keys(), ['access_token', 'token_type', 'expires_in',
                            'refresh_token'])

    uec = at.to_urlencoded()
    raises(ValueError, 'client.parse_response(ATR, info=uec)')

    uatr = client.parse_response(ATR, info=uec, format="urlencoded")
    assert _eq(uatr.keys(), ['access_token', 'token_type', 'expires_in',
                             'refresh_token'])

    huec = "%s?%s" % ("https://example.com/token", uec)

    uatr = client.parse_response(ATR, info=huec, format="urlencoded")
    assert _eq(uatr.keys(), ['access_token', 'token_type', 'expires_in',
                             'refresh_token'])

    err = message_from_schema(OA2_SCHEMA["ErrorResponse"],
                              error="invalid_request",
                              error_description="Something was missing", 
                              error_uri="http://example.com/error_message.html")

    jerr = err.to_json()
    uerr = err.to_urlencoded()

    _ = client.parse_response(ATR, info=jerr)
    _ = client.parse_response(ATR, info=uerr, format="urlencoded")

    raises(Exception,
           'client.parse_response(ATR, info=jerr, format="urlencoded")')

    raises(Exception, "client.parse_response(ATR, info=uerr)")

    raises(Exception,
           'client.parse_response(ATR, info=jerr, format="focus")')

#noinspection PyUnusedLocal
def test_parse_access_token_response_missing_attribute():
    at = message("AccessTokenResponse", access_token="SlAV32hkKG",
                 token_type="Bearer", refresh_token="8xLOxBtZp8",
                 expires_in=3600)

    atdict = at.to_dict()
    del atdict["access_token"]
    atj = json.dumps(atdict)
    print atj
    client = Client()
    ATR = SCHEMA["AccessTokenResponse"]

    raises(MissingRequiredAttribute, "client.parse_response(ATR, info=atj)")

    atuec = urllib.urlencode(atdict)

    raises(MissingRequiredAttribute,
           "client.parse_response(ATR, info=atuec, format='urlencoded')")


def test_client_get_grant():
    cli = Client()

    resp = message("AuthorizationResponse", code="code", state="state")
    grant = Grant()
    grant.add_code(resp)

    cli.grant["state"] = grant

    gr1 = cli.grant_from_state("state")

    assert gr1.code == "code"

def test_client_parse_args():
    cli = Client()

    args = {
        "response_type":"",
        "client_id":"client_id",
        "redirect_uri": "http://example.com/authz",
        "scope":"scope",
        "state":"state",
        }
    ar_args = cli._parse_args(SCHEMA["AuthorizationRequest"], **args)

    print ar_args.keys()
    assert _eq(ar_args.keys(), ['scope', 'state', 'redirect_uri',
                                'response_type', 'client_id'])

def test_client_parse_extra_args():
    cli = Client()

    args = {
        "response_type":"",
        "client_id":"client_id",
        "redirect_uri": "http://example.com/authz",
        "scope":"scope",
        "state":"state",
        "extra_session": "home"
    }
    ar_args = cli._parse_args(SCHEMA["AuthorizationRequest"], **args)

    print ar_args.keys()
    assert _eq(ar_args.keys(), ['state', 'redirect_uri', 'response_type',
                                'client_id', 'scope', 'extra_session'])

def test_client_endpoint():
    cli = Client()
    cli.authorization_endpoint = "https://example.org/oauth2/as"
    cli.token_endpoint = "https://example.org/oauth2/token"
    cli.token_revocation_endpoint = "https://example.org/oauth2/token_rev"

    ae = cli._endpoint("authorization_endpoint")
    assert ae == "https://example.org/oauth2/as"
    te = cli._endpoint("token_endpoint")
    assert te == "https://example.org/oauth2/token"
    tre = cli._endpoint("token_revocation_endpoint")
    assert tre == "https://example.org/oauth2/token_rev"

    ae = cli._endpoint("authorization_endpoint", **{
        "authorization_endpoint": "https://example.com/as"})
    assert ae == "https://example.com/as"

    cli.token_endpoint = ""
    raises(Exception, 'cli._endpoint("token_endpoint")')
    raises(Exception, 'cli._endpoint("foo_endpoint")')


def test_server_parse_parse_authorization_request():
    srv = Server()
    ar = message("AuthorizationRequest", response_type=["code"],
                 client_id="foobar",
                 redirect_uri="http://foobar.example.com/oaclient",
                 state="cold", nonce="NONCE")

    uencq = ar.to_urlencoded()

    areq = srv.parse_authorization_request(query=uencq)

    assert areq.type() == "AuthorizationRequest"
    assert areq["response_type"] == ["code"]
    assert areq["client_id"] == "foobar"
    assert areq["redirect_uri"] == "http://foobar.example.com/oaclient"
    assert areq["state"] == "cold"

    urluenc = "%s?%s" % ("https://example.com/authz", uencq)

    areq = srv.parse_authorization_request(url=urluenc)

    assert areq.type() == "AuthorizationRequest"
    assert areq["response_type"] == ["code"]
    assert areq["client_id"] == "foobar"
    assert areq["redirect_uri"] == "http://foobar.example.com/oaclient"
    assert areq["state"] == "cold"

def test_server_parse_jwt_request():
    srv = Server(KEYS)
    ar = message("AuthorizationRequest", response_type=["code"],
                 client_id="foobar",
                 redirect_uri="http://foobar.example.com/oaclient",
                 state="cold", nonce="NONCE")

    _keys = srv.keystore.get_verify_key(owner=CLIENT_ID)
    _jwt = ar.to_jwt(key=_keys, algorithm="HS256")

    req = srv.parse_jwt_request(txt=_jwt)

    assert req.type() == "AuthorizationRequest"
    assert req["response_type"] == ["code"]
    assert req["client_id"] == "foobar"
    assert req["redirect_uri"] == "http://foobar.example.com/oaclient"
    assert req["state"] == "cold"

def test_server_parse_token_request():
    atr = message("AccessTokenRequest", grant_type="authorization_code",
                  code="SplxlOBeZQQYbYS6WxSbIA",
                  redirect_uri="https://client.example.com/cb",
                  client_id="client_id", extra="foo")

    uenc = atr.to_urlencoded()

    srv = Server()
    tr = srv.parse_token_request(body=uenc)
    print tr.keys()

    assert tr.type() == "AccessTokenRequest"
    assert _eq(tr.keys(), ['code', 'redirect_uri', 'grant_type', 'client_id',
                           'extra'])

    assert tr["grant_type"] == "authorization_code"
    assert tr["code"] == "SplxlOBeZQQYbYS6WxSbIA"

    tr = srv.parse_token_request(body=uenc)
    print tr.keys()

    assert tr.type() == "AccessTokenRequest"
    assert _eq(tr.keys(), ['code', 'grant_type', 'client_id', 'redirect_uri',
                           'extra'])

    assert tr["extra"] == "foo"

def test_server_parse_refresh_token_request():
    ratr = message("RefreshAccessTokenRequest", refresh_token="ababababab",
                   client_id="Client_id")

    uenc = ratr.to_urlencoded()

    srv = Server()
    tr = srv.parse_refresh_token_request(body=uenc)
    print tr.keys()

    assert tr.type() == "RefreshAccessTokenRequest"
    assert tr["refresh_token"] == "ababababab"
    assert tr["client_id"] == "Client_id"

def test_construct_UserInfoRequest():
    cli = Client()
    cli.userinfo_endpoint = "https://example.org/oauth2/userinfo"

    uir = cli.construct_UserInfoRequest(
        request_args={"access_token":"access_token"})
    print uir
    assert ("%s" % uir) == "access_token=access_token"

def test_construct_UserInfoRequest_2():
    cli = Client()
    cli.userinfo_endpoint = "https://example.org/oauth2/userinfo"
    cli.grant["foo"] = Grant()
    cli.grant["foo"].grant_expiration_time = time.time()+60
    cli.grant["foo"].code = "access_code"

    resp = message("AccessTokenResponse", refresh_token="refresh_with_me",
                   access_token="access", id_token="IDTOKEN",
                   scope=["openid"])

    cli.grant["foo"].tokens.append(Token(resp))

    uir = cli.construct_UserInfoRequest(state="foo", scope=["openid"])
    print uir
    assert uir.keys() == ["access_token"]

def test_construct_CheckSessionRequest():
    cli = Client()
    cli.check_session_endpoint = "https://example.org/oauth2/check_session"

    csr = cli.construct_CheckSessionRequest(
        request_args={"id_token":"id_token"})
    print csr
    assert ("%s" % csr) == 'id_token=id_token'

def test_construct_CheckSessionRequest_2():
    cli = Client()
    cli.userinfo_endpoint = "https://example.org/oauth2/userinfo"
    cli.grant["foo"] = Grant()
    cli.grant["foo"].grant_expiration_time = time.time()+60
    cli.grant["foo"].code = "access_code"

    resp = message("AccessTokenResponse", id_token = "id_id_id_id",
                   access_token = "access", scope = ["openid"])

    cli.grant["foo"].tokens.append(Token(resp))

    uir = cli.construct_CheckSessionRequest(state="foo", scope=["openid"])
    print uir
    assert ("%s" % uir) == "id_token=id_id_id_id"

def test_construct_RegistrationRequest():
    cli = Client()
    cli.redirect_uris = ["http://example.com/authz"]

    request_args = {
        "type":"client_associate",
        "client_id":CLIENT_ID,
        "contacts":["foo@example.com"],
        "application_type":"web",
        "application_name":"EXAMPLE OIC service",
        }

    crr = cli.construct_RegistrationRequest(request_args=request_args)

    print crr.keys()
    assert _eq(crr.keys(), ['application_name', 'application_type', 'type',
                            'client_id', 'contacts', 'redirect_uris'])


def test_construct_EndSessionRequest():
    cli = Client()
    cli.redirect_uris = ["http://example.com/authz"]
    cli.grant["foo"] = Grant()
    cli.grant["foo"].grant_expiration_time = time.time()+60
    cli.grant["foo"].code = "access_code"

    resp = message("AccessTokenResponse", id_token = "id_id_id_id",
                   access_token = "access", scope = ["openid"])

    cli.grant["foo"].tokens.append(Token(resp))

    args = {"redirect_url":"http://example.com/end"}
    esr = cli.construct_EndSessionRequest(state="foo", request_args=args)
    print esr.keys()
    assert _eq(esr.keys(), ['id_token', 'state', "redirect_url"])

def test_construct_OpenIDRequest():
    cli = Client()
    cli.client_id = CLIENT_ID
    cli.client_secret = CLIENT_SECRET
    cli.scope = ["openid", "profile"]
    cli.redirect_uris= ["https://client.example.com/cb"]

    request_args = {"response_type": "code id_token", "state": "af0ifjsldkj" }

    oidr = cli.construct_OpenIDRequest(request_args=request_args)
    print oidr.keys()
    assert _eq(oidr.keys(), ['nonce', 'state', 'redirect_uri', 'response_type',
                             'client_id', 'scope'])

ARESP = message("AuthorizationResponse", code="code", state="state000")
TRESP = message("AccessTokenResponse", access_token="access_token",
                token_type="bearer", expires_in=600, refresh_token="refresh",
                scope=["openid"])

def test_userinfo_request():
    cli = Client()
    cli.userinfo_endpoint = "http://example.com/userinfo"

    info = ARESP.to_urlencoded()
    cli.parse_response(SCHEMA["AuthorizationResponse"], info,
                       format="urlencoded", state="state0")

    cli.parse_response(SCHEMA["AccessTokenResponse"], TRESP.to_json(),
                       state="state0")

    path, body, method, h_args = cli.user_info_request(state="state0",
                                                       schema="openid")

    assert path == "http://example.com/userinfo?access_token=access_token&schema=openid"
    assert method == "GET"
    assert body is None
    assert h_args == {}


    path, body, method, h_args = cli.user_info_request(method="POST",
                                                       state="state0",
                                                       schema="openid")

    assert path == "http://example.com/userinfo"
    assert method == "POST"
    assert body == "access_token=access_token&schema=openid"
    assert h_args == {'headers': {'content-type': 'application/x-www-form-urlencoded'}}


    path, body, method, h_args = cli.user_info_request(method="POST",
                                                       state="state0")

    assert path == "http://example.com/userinfo"
    assert method == "POST"
    assert body == "access_token=access_token"
    assert h_args == {'headers': {'content-type': 'application/x-www-form-urlencoded'}}

#def test_do_user_indo_request():
#    cli = Client()
#    cli.userinfo_endpoint = "http://example.com/userinfo"
#
#    cli.http = MyFakeOICServer(KEYS)

# ----------------------------------------------------------------------------

TREQ = message("AccessTokenRequest", code="code",
               redirect_uri="http://example.com/authz", client_id=CLIENT_ID)

AREQ = message("AuthorizationRequest", response_type="code",
               client_id="client_id",
               redirect_uri="http://example.com/authz", scope=["openid"],
               state="state0", nonce="N0nce")

UIREQ = message("UserInfoRequest", access_token="access_token",
                schema="openid")

REGREQ = message("RegistrationRequest", contacts=["roland.hedberg@adm.umu.se"],
                 redirect_uris=["http://example.org/jqauthz"],
                 application_name="pacubar", client_id=CLIENT_ID,
                 type="client_associate")

RSREQ = message("RefreshSessionRequest", id_token="id_token",
                redirect_url="http://example.com/authz", state="state0")

#key, type, usage, owner="."

CSREQ = message("CheckSessionRequest",id_token=IDTOKEN.to_jwt(key=SIGN_KEY))

ESREQ = message("EndSessionRequest", id_token=IDTOKEN.to_jwt(key=SIGN_KEY),
                redirect_url="http://example.org/jqauthz", state="state0")

IDT2 = message("IDTokenClaim", max_age=86400)

CLAIM = message("Claims", name=None, nickname={"optional": True}, email=None,
               verified=None, picture={"optional": True})

USRINFO = message("UserInfoClaim", claims=CLAIM, format="signed")

OIDREQ = message("OpenIDRequest", response_type=["code", "id_token"],
                 client_id=CLIENT_ID,
                 redirect_uri="https://client.example.com/cb",
                 scope="openid profile", state= "n-0S6_WzA2Mj",
                 nonce="af0ifjsldkj", userinfo=USRINFO, id_token=IDT2)

def test_server_init():

    srv = Server()
    assert srv

    srv = Server(KEYS)
    assert srv

def test_parse_urlencoded():
    loc = "http://example.com/userinfo?access_token=access_token&schema=openid"
    srv = Server()
    qdict = srv._parse_urlencoded(loc)
    assert _eq(qdict.keys(),["access_token", "schema"])
    # all values as lists
    assert qdict["schema"] == ["openid"]
    assert qdict["access_token"] == ["access_token"]

def test_parse_authorization_request():
    srv = Server()
    qdict = srv.parse_authorization_request(query=AREQ.to_urlencoded())
    assert _eq(qdict.keys(),['nonce', 'state', 'redirect_uri', 'response_type',
                             'client_id', 'scope'])
    assert qdict["state"] == "state0"

def test_parse_token_request():
    srv = Server()
    qdict = srv.parse_token_request(body=TREQ.to_urlencoded())
    assert qdict.type() == "AccessTokenRequest"
    assert _eq(qdict.keys(),['code', 'redirect_uri', 'client_id', 'grant_type'])
    assert qdict["client_id"] == CLIENT_ID
    assert qdict["code"] == "code"

def test_parse_userinfo_request():
    srv = Server()
    qdict = srv.parse_user_info_request(data=UIREQ.to_urlencoded())
    assert _eq(qdict.keys(),['access_token', 'schema'])
    assert qdict["access_token"] == "access_token"
    assert qdict["schema"] == "openid"

    url = "https://example.org/userinfo?%s" % UIREQ.to_urlencoded()
    qdict = srv.parse_user_info_request(data=url)
    assert _eq(qdict.keys(),['access_token', 'schema'])
    assert qdict["access_token"] == "access_token"
    assert qdict["schema"] == "openid"

def test_parse_registration_request():
    srv = Server()
    request = srv.parse_registration_request(data=REGREQ.to_urlencoded())
    assert request.type() == "RegistrationRequest"
    assert _eq(request.keys(),['redirect_uris', 'contacts', 'client_id',
                               'application_name', 'type'])
    assert request["application_name"] == "pacubar"
    assert request["type"] == "client_associate"

def test_parse_refresh_session_request():
    srv = Server()
    request = srv.parse_refresh_session_request(query=RSREQ.to_urlencoded())
    assert request.type() == "RefreshSessionRequest"
    assert _eq(request.keys(),['id_token', 'state', 'redirect_url'])
    assert request["id_token"] == "id_token"

    url = "https://example.org/userinfo?%s" % RSREQ.to_urlencoded()
    request = srv.parse_refresh_session_request(url=url)
    assert request.type() == "RefreshSessionRequest"
    assert _eq(request.keys(),['id_token', 'state', 'redirect_url'])
    assert request["id_token"] == "id_token"

def test_parse_check_session_request():
    srv = Server(KEYS)
    request = srv.parse_check_session_request(query=CSREQ.to_urlencoded())
    assert request.type() == "IdToken"
    assert _eq(request.keys(),['nonce', 'user_id', 'aud', 'iss', 'exp'])
    assert request["aud"] == "client_1"

def test_parse_end_session_request():
    srv = Server(KEYS)
    request = srv.parse_end_session_request(query=ESREQ.to_urlencoded())
    assert request.type() == "EndSessionRequest"
    assert _eq(request.keys(),['id_token', 'redirect_url', 'state'])
    assert request["state"] == "state0"

    assert request["id_token"]["aud"] == "client_1"

def test_parse_open_id_request():
    srv = Server(KEYS)
    request = srv.parse_open_id_request(data=OIDREQ.to_urlencoded())
    assert request.type() == "OpenIDRequest"
    print request.keys()
    assert _eq(request.keys(),['nonce', 'id_token', 'userinfo', 'state',
                               'redirect_uri', 'response_type', 'client_id',
                               'scope'])
    assert request["state"] == "n-0S6_WzA2Mj"

    print request["userinfo"]

    assert request["userinfo"]["claims"]["nickname"] == {'optional': True}

    request = srv.parse_open_id_request(data=OIDREQ.to_json(), format="json")
    assert request.type() == "OpenIDRequest"
    print request.keys()
    assert _eq(request.keys(),['nonce', 'id_token', 'userinfo', 'state',
                               'redirect_uri', 'response_type', 'client_id',
                               'scope'])
    assert request["nonce"] == "af0ifjsldkj"

    print request["userinfo"]

    #assert request.userinfo.format == "signed"
    print request["userinfo"]["claims"].to_dict()
    assert "email" in request["userinfo"]["claims"]

    url = "https://example.org/openid?%s" % OIDREQ.to_urlencoded()
    request = srv.parse_open_id_request(url)
    assert request.type() == "OpenIDRequest"
    print request.keys()
    assert _eq(request.keys(),['nonce', 'id_token', 'userinfo', 'state',
                               'redirect_uri', 'response_type', 'client_id',
                               'scope'])
    assert request["state"] == "n-0S6_WzA2Mj"

    print request["userinfo"]

    #assert request.userinfo.format == "signed"
    assert request["userinfo"]["claims"]["nickname"] == {"optional": True}

    raises(Exception, 'srv.parse_open_id_request(url, format="base64")')