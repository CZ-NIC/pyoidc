#!/usr/bin/env python

__author__ = 'rohe0002'

import time
import base64
import random
import hmac
import hashlib
import json
import urllib

from oic import oauth2
from oic.oauth2 import Grant
from oic.utils import time_util
from oic.oauth2 import Client
from oic.oauth2 import Server
from oic.oauth2 import Token
from oic.oauth2.message import message
from oic.oauth2.message import SCHEMA

from oic.utils.sdb import Crypt

from pytest import raises

def _eq(l1, l2):
    return set(l1) == set(l2)

# ----------------- GRANT --------------------

acc_tok_resp = message("AccessTokenResponse",
    access_token="2YotnFZFEjr1zCsicMWpAA",
    token_type="example",
    refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
    example_parameter="example_value",
    scope=["inner", "outer"])

def test_grant():
    grant = Grant()
    assert grant
    assert grant.exp_in == 600

    grant = Grant(60)
    assert grant.exp_in == 60

def test_grant_from_code():
    ar = message("AuthorizationResponse", code="code", state="state")

    grant = Grant.from_code(ar)

    assert grant
    assert grant.code == "code"

def test_grant_add_code():
    ar = message("AuthorizationResponse", code="code", state="state")

    grant = Grant()
    grant.add_code(ar)
    assert grant
    assert grant.code == "code"

def test_grant_update():
    ar = message("AuthorizationResponse", code="code", state="state")

    grant = Grant()
    grant.update(ar)

    assert grant
    assert grant.code == "code"

def test_grant_set():
    ar = message("AuthorizationResponse", code="code", state="state")

    grant = Grant.from_code(ar)

    assert grant
    assert grant.code == "code"

def test_grant_add_token():

    grant = Grant()
    grant.update(acc_tok_resp)

    assert len(grant.tokens) == 1
    token = grant.tokens[0]

    assert token.access_token == "2YotnFZFEjr1zCsicMWpAA"
    assert token.token_type == "example"
    assert token.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"

def test_grant_set_3():
    err = message("ErrorResponse", error="invalid_request")
    grant = Grant()
    grant.update(err)

    assert len(grant.tokens) == 0



# ----------------- CLIENT --------------------

class TestOAuthClient():
    def setup_class(self):
        self.client = Client("1")
        self.client.redirect_uris = ["http://example.com/redirect"]

    def test_areq_1(self):
        ar = self.client.construct_AuthorizationRequest(
                                    request_args={"response_type":["code"]})

        assert ar["redirect_uri"] == "http://example.com/redirect"
        assert ar["response_type"] == ["code"]
        assert ar["client_id"] == "1"
        assert "state" not in ar
        assert "scope" not in ar

    def test_areq_2(self):
        self.client.state = "abc"
        req_args = {"response_type":["code"], "scope": ["foo", "bar"]}
        ar = self.client.construct_AuthorizationRequest(request_args=req_args)

        assert ar["redirect_uri"] == "http://example.com/redirect"
        assert ar["response_type"] == ["code"]
        assert ar["client_id"] == "1"
        assert ar["state"] == "abc"
        assert ar["scope"] == ["foo", "bar"]

    def test_areq_replace_default_state(self):
        self.client.state = "efg"
        req_args = {"response_type":["code"], "scope": ["foo", "bar"]}
        ar = self.client.construct_AuthorizationRequest(request_args=req_args)

        assert ar["redirect_uri"] == "http://example.com/redirect"
        assert ar["response_type"] == ["code"]
        assert ar["client_id"] == "1"
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
        assert atr["client_id"] == "1"

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
        resp = message("AccessTokenResponse",
                       refresh_token = "refresh_with_me",
                       access_token = "access")

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
        print self.client.__dict__.items()
        req = self.client.construct_AccessTokenRequest(state="foo",
                                                       extra_args={"foo":"bar"})

        assert req
        print req.keys()
        assert _eq(req.keys(), ['code', 'grant_type', 'client_id',
                                'redirect_uri', 'foo'])
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
        assert body == "redirect_uri=http%3A%2F%2Fclient.example.com%2Fauthz&response_type=code&client_id=1"
        assert h_args == {'headers': {'content-type': 'application/x-www-form-urlencoded'}}
        assert cis.type() == "AuthorizationRequest"

    def test_request_info_simple_get(self):
        #self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(
                                                SCHEMA["AuthorizationRequest"],
                                                method="GET")

        assert uri == 'https://example.com/authz?redirect_uri=http%3A%2F%2Fclient.example.com%2Fauthz&response_type=code&client_id=1'
        assert body is None
        assert h_args == {}
        assert cis.type() == "AuthorizationRequest"

    def test_request_info_simple_get_with_req_args(self):
        #self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(
                                                SCHEMA["AuthorizationRequest"],
                                                method="GET",
                                                request_args={"state":"init"})

        print uri
        assert uri == 'https://example.com/authz?state=init&redirect_uri=http%3A%2F%2Fclient.example.com%2Fauthz&response_type=code&client_id=1'
        assert body is None
        assert h_args == {}
        assert cis.type() == "AuthorizationRequest"

    def test_request_info_simple_get_with_extra_args(self):
        #self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(
                                                SCHEMA["AuthorizationRequest"],
                                                method="GET",
                                                extra_args={"rock":"little"})

        print uri
        assert uri == 'https://example.com/authz?redirect_uri=http%3A%2F%2Fclient.example.com%2Fauthz&response_type=code&client_id=1&rock=little'
        assert body is None
        assert h_args == {}
        assert cis.type() == "AuthorizationRequest"

    def test_request_info_with_req_and_extra_args(self):
        #self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(
            SCHEMA["AuthorizationRequest"],
            method="GET",
            request_args={"state":"init"},
            extra_args={"rock":"little"})

        print uri
        assert uri == 'https://example.com/authz?state=init&redirect_uri=http%3A%2F%2Fclient.example.com%2Fauthz&response_type=code&client_id=1&rock=little'
        assert body is None
        assert h_args == {}
        assert cis.type() == "AuthorizationRequest"

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
    try:
        client.construct_AccessTokenRequest(state="openid")
    except Exception, err:
        assert err.__class__.__name__ == "GrantExpired"

def test_parse_access_token_response():
    client = Client()

    at = message("AccessTokenResponse", access_token="SlAV32hkKG",
                 token_type="Bearer", refresh_token="8xLOxBtZp8",
                 expire_in=3600)

    atj = at.to_json()

    ATR = SCHEMA["AccessTokenResponse"]
    atr = client.parse_response(ATR, info=atj)

    assert _eq(atr.keys(), ['access_token', 'token_type', u'expire_in',
                            'refresh_token'])

    uec = at.to_urlencoded()
    raises(ValueError, 'client.parse_response(ATR, info=uec)')

    uatr = client.parse_response(ATR, info=uec, format="urlencoded")
    assert _eq(uatr.keys(), ['access_token', 'token_type', 'expire_in',
                             'refresh_token'])

    huec = "%s?%s" % ("https://example.com/token", uec)

    uatr = client.parse_response(ATR, info=huec, format="urlencoded")
    assert _eq(uatr.keys(), ['access_token', 'token_type', 'expire_in',
                             'refresh_token'])

    err = message("ErrorResponse", error="invalid_request",
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
                 expire_in=3600)

    atdict = at.to_dict()
    del atdict["access_token"]
    atj = json.dumps(atdict)
    print atj
    client = Client()
    ATR = SCHEMA["AccessTokenResponse"]

    try:
        client.parse_response(ATR, info=atj)
    except Exception, err:
        assert err.__class__.__name__ == "MissingRequiredAttribute"

    atuec = urllib.urlencode(atdict)

    try:
        client.parse_response(ATR, info=atuec, format='urlencoded')
    except Exception, err:
        assert err.__class__.__name__ == "MissingRequiredAttribute"

def test_crypt():
    crypt = Crypt("4-amino-1H-pyrimidine-2-one")
    ctext = crypt.encrypt("Cytosine")
    plain = crypt.decrypt(ctext)
    print plain
    assert plain == 'Cytosine        '

    ctext = crypt.encrypt("cytidinetriphosp")
    plain = crypt.decrypt(ctext)

    assert plain == 'cytidinetriphosp'

def test_crypt2():
    db = {}
    csum = hmac.new("secret", digestmod=hashlib.sha224)
    csum.update("%s" % time.time())
    csum.update("%f" % random.random())
    txt = csum.digest() # 28 bytes long, 224 bits
    print len(txt)
    db[txt] = "foobar"
    txt = "%saces" % txt # another 4 bytes
    #print len(txt), txt
    crypt = Crypt("4-amino-1H-pyrimidine-2-one")
    ctext = crypt.encrypt(txt)
    onthewire = base64.b64encode(ctext)
    #print onthewire
    plain = crypt.decrypt(base64.b64decode(onthewire))
    #print len(plain), plain
    #assert plain == txt
    assert plain.endswith("aces")
    assert db[plain[:-4]] == "foobar"


def test_grant_init():
    grant = Grant()
    assert grant.grant_expiration_time == 0

    grant = Grant()
    assert grant.grant_expiration_time == 0

def test_grant_resp():
    resp = message("AuthorizationResponse", code="code", state="state")
    grant = Grant()
    grant.add_code(resp)

    assert grant.code == "code"
    assert grant.grant_expiration_time != 0

    grant = Grant(1)
    grant.add_code(resp)
    time.sleep(2)

    assert grant.is_valid() == False

    grant = Grant.from_code(resp)
    assert grant.code == "code"
    assert grant.grant_expiration_time != 0


def test_grant_access_token_1():
    resp = message("AuthorizationResponse", code="code", state="state")
    grant = Grant()
    grant.add_code(resp)

    atr = message("AccessTokenResponse", access_token="2YotnFZFEjr1zCsicMWpAA",
                  token_type="example", expires_in=1,
                  refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                  example_parameter="example_value", xscope=["inner", "outer"])

    token = Token(atr)
    grant.tokens.append(token)

    print grant.keys()
    assert _eq(grant.keys(), ['tokens', 'id_token', 'code', 'exp_in', 'seed',
                              'grant_expiration_time'])
    print token.keys()
    assert _eq(token.keys(), ['token_expiration_time', 'access_token',
                              'expires_in', 'example_parameter', 'token_type',
                              'xscope', 'refresh_token', 'scope',
                              'replaced'])

    assert token.access_token == "2YotnFZFEjr1zCsicMWpAA"
    assert token.token_type == "example"
    assert token.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"
    assert token.example_parameter == "example_value"
    assert token.xscope == ["inner", "outer"]
    assert token.token_expiration_time != 0

    time.sleep(2)
    assert token.is_valid() == False

def test_grant_access_token_2():
    resp = message("AuthorizationResponse", code="code", state="state")
    grant = Grant()
    grant.add_code(resp)

    atr = message("AccessTokenResponse",
        access_token="2YotnFZFEjr1zCsicMWpAA",
        token_type="example",
        refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
        example_parameter="example_value",
        scope=["inner", "outer"])

    grant.add_token(atr)

    assert len(grant.tokens) == 1
    time.sleep(2)
    token = grant.tokens[0]
    assert token.is_valid() == True

    assert "%s" % grant != ""

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
        "redirect_uri":"http://example.com/authz",
        "scope":"scope",
        "state":"state",
        }

    ar_args = cli._parse_args(SCHEMA["AuthorizationRequest"], **args)

    assert _eq(ar_args.keys(), ['scope', 'state', 'redirect_uri',
                                'response_type', 'client_id'])

def test_client_parse_extra_args():
    cli = Client()

    args = {
        "response_type":"",
        "client_id":"client_id",
        "redirect_uri":"http://example.com/authz",
        "scope":"scope",
        "state":"state",
        "extra_session": "home"
    }
    ar_args = cli._parse_args(SCHEMA["AuthorizationRequest"], **args)

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
                 state="cold")

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
    srv = Server()
    ar = message("AuthorizationRequest", response_type=["code"],
                 client_id="foobar",
                 redirect_uri="http://foobar.example.com/oaclient",
                 state="cold")

    srv.keystore.set_verify_key("A1B2C3D4", owner="foobar")
    srv.keystore.set_sign_key("A1B2C3D4", owner="foobar")

    keys = srv.keystore.get_sign_key(owner="foobar")
    _jwt = ar.to_jwt(key=keys, algorithm="HS256")

    req = srv.parse_jwt_request(txt=_jwt)

    assert req.type() == "AuthorizationRequest"
    assert req["response_type"] == ["code"]
    assert req["client_id"] == "foobar"
    assert req["redirect_uri"] == "http://foobar.example.com/oaclient"
    assert req["state"] == "cold"

def test_server_parse_token_request():
    atr = message("AccessTokenRequest", grant_type="authorization_code",
                  code="SplxlOBeZQQYbYS6WxSbIA",
                  redirect_uri="https://client.example.com/cb", extra="foo")

    uenc = atr.to_urlencoded()

    srv = Server()
    tr = srv.parse_token_request(body=uenc)
    print tr.keys()

    assert tr.type() == "AccessTokenRequest"
    assert _eq(tr.keys(), ['code', 'redirect_uri', 'grant_type', 'extra'])

    assert tr["grant_type"] == "authorization_code"
    assert tr["code"] == "SplxlOBeZQQYbYS6WxSbIA"

    tr = srv.parse_token_request(body=uenc)
    print tr.keys()

    assert tr.type() == "AccessTokenRequest"
    assert _eq(tr.keys(), ['code', 'grant_type', 'redirect_uri', 'extra'])

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

def test_client_secret_post():
    client = Client("A")
    client.client_secret = "boarding pass"

    cis = message("AccessTokenRequest",code="foo",
                  redirect_uri="http://example.com")

    http_args = oauth2.client_secret_post(client, cis)

    print cis
    assert cis["client_id"] == "A"
    assert cis["client_secret"] == "boarding pass"
    print http_args
    assert http_args is None

    cis = message("AccessTokenRequest", code="foo",
                  redirect_uri="http://example.com")

    request_args = {}
    http_args = oauth2.client_secret_post(client, cis, request_args,
                                          http_args={"client_secret": "another"})

    print cis
    assert cis["client_id"] == "A"
    assert cis["client_secret"] == "another"
    print http_args
    assert http_args == {}


def test_bearer_header():
    client = Client("A")
    client.client_secret = "boarding pass"

    request_args = {"access_token": "Sesame"}

    cis = message("ResourceRequest")

    http_args = oauth2.bearer_header(client, cis, request_args)

    print cis
    print http_args
    assert http_args == {"headers": {"Authorization":"Bearer Sesame"}}

def test_bearer_body():
    client = Client("A")
    client.client_secret = "boarding pass"

    request_args = {"access_token": "Sesame"}

    cis = message("ResourceRequest")
    http_args = oauth2.bearer_body(client, cis, request_args)
    assert cis["access_token"] == "Sesame"
    print http_args
    assert http_args is None

    # ----------
    resp = message("AuthorizationResponse", code="code", state="state")
    grant = Grant()
    grant.add_code(resp)

    atr = message("AccessTokenResponse",
                  access_token="2YotnFZFEjr1zCsicMWpAA", token_type="example",
                  refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                  example_parameter="example_value",
                  scope=["inner", "outer"])

    grant.add_token(atr)
    client.grant["state"] = grant

    cis = message("ResourceRequest")
    http_args = oauth2.bearer_body(client, cis, {}, state="state",
                                   scope="inner")
    assert cis["access_token"] == "2YotnFZFEjr1zCsicMWpAA"
    print http_args
    assert http_args is None
