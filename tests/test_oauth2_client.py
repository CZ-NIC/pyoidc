#!/usr/bin/env python

__author__ = 'rohe0002'

from oic import oauth2
from oic.utils import time_util
import time
import json
import urllib

from pytest import raises

def _eq(l1, l2):
    return set(l1) == set(l2)

# ----------------- GRANT --------------------

acc_tok_resp = oauth2.AccessTokenResponse(
                            access_token="2YotnFZFEjr1zCsicMWpAA",
                            token_type="example",
                            refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                            example_parameter="example_value",
                            scope=["inner", "outer"])

def test_grant():
    grant = oauth2.Grant()
    assert grant
    assert grant.state == ""
    assert grant.gexp_in == 600

    grant = oauth2.Grant("foobar", 60)
    assert grant.state == "foobar"
    assert grant.gexp_in == 60

def test_grant_from_code():
    ar = oauth2.AuthorizationResponse("code", "state")

    grant = oauth2.Grant.from_code(ar)

    assert grant
    assert grant.code == "code"

def test_grant_add_code():
    ar = oauth2.AuthorizationResponse("code", "state")

    grant = oauth2.Grant()
    grant.add_code(ar)
    assert grant
    assert grant.code == "code"

def test_grant_update():
    ar = oauth2.AuthorizationResponse("code", "state")

    grant = oauth2.Grant()
    grant.update(ar)

    assert grant
    assert grant.code == "code"

def test_grant_set():
    ar = oauth2.AuthorizationResponse("code", "state")

    grant = oauth2.Grant.set(ar)

    assert grant
    assert grant.code == "code"

def test_grant_from_token():
    grant = oauth2.Grant.from_token(acc_tok_resp)

    assert grant
    assert _eq(grant.keys(), ['token_expiration_time', 'access_token',
                              'example_parameter', 'token_type',
                              'grant_expiration_time', 'state',
                              'scope', 'gexp_in', 'refresh_token'])
    assert grant.access_token == "2YotnFZFEjr1zCsicMWpAA"
    assert grant.token_type == "example"
    assert grant.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"
    assert grant.example_parameter == "example_value"
    assert grant.scope == ["inner", "outer"]

def test_grant_add_token():

    grant = oauth2.Grant()
    grant.add_token(acc_tok_resp)

    assert grant.access_token == "2YotnFZFEjr1zCsicMWpAA"
    assert grant.token_type == "example"
    assert grant.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"

def test_grant_update_2():
    grant = oauth2.Grant()
    grant.update(acc_tok_resp)

    assert grant.access_token == "2YotnFZFEjr1zCsicMWpAA"
    assert grant.token_type == "example"
    assert grant.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"

def test_grant_set_2():
    grant = oauth2.Grant.set(acc_tok_resp)

    assert grant.access_token == "2YotnFZFEjr1zCsicMWpAA"
    assert grant.token_type == "example"
    assert grant.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"

def test_grant_set_3():
    err = oauth2.ErrorResponse(error="invalid_request")
    
    assert oauth2.Grant.set(err) is None



# ----------------- CLIENT --------------------

class TestOAuthClient():
    def setup_class(self):
        self.client = oauth2.Client("1")
        self.client.redirect_uri = "http://example.com/redirect"

    def test_areq_1(self):
        ar = self.client.construct_AuthorizationRequest(
                                    request_args={"response_type":["code"]})

        assert ar.redirect_uri == "http://example.com/redirect"
        assert ar.response_type == ["code"]
        assert ar.client_id == "1"
        assert ar.state is None
        assert ar.scope == []
        
    def test_areq_2(self):
        self.client.state = "abc"
        req_args = {"response_type":["code"], "scope": ["foo", "bar"]}
        ar = self.client.construct_AuthorizationRequest(request_args=req_args)

        assert ar.redirect_uri == "http://example.com/redirect"
        assert ar.response_type == ["code"]
        assert ar.client_id == "1"
        assert ar.state == "abc"
        assert ar.scope == ["foo", "bar"]

    def test_areq_replace_default_state(self):
        self.client.state = "efg"
        req_args = {"response_type":["code"], "scope": ["foo", "bar"]}
        ar = self.client.construct_AuthorizationRequest(request_args=req_args)

        assert ar.redirect_uri == "http://example.com/redirect"
        assert ar.response_type == ["code"]
        assert ar.client_id == "1"
        assert ar.state == "efg"
        assert ar.scope == ["foo", "bar"]

    def test_parse_authz_resp_url(self):
        url = "https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=ghi"
        aresp = self.client.parse_response(oauth2.AuthorizationResponse,
                                            info=url, format="urlencoded")

        assert aresp.code == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp.state == "ghi"

        assert self.client.grant[""]
        assert self.client.grant[""].code == aresp.code
        assert self.client.grant[""].grant_expiration_time

    def test_parse_authz_resp_query(self):
        query = "code=SplxlOBeZQQYbYS6WxSbIA&state=hij"
        aresp = self.client.parse_response(oauth2.AuthorizationResponse,
                                            info=query, format="urlencoded",
                                            scope="foo")

        assert aresp.code == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp.state == "hij"

        print self.client.grant.keys()
        assert self.client.grant["foo"]
        assert self.client.grant["foo"].code == aresp.code
        assert self.client.grant["foo"].grant_expiration_time

    def test_parse_authz_resp_query_multi_scope(self):
        query = "code=SplxlOBeZQQYbYS6WxAAAA&state=klm"
        aresp = self.client.parse_response(oauth2.AuthorizationResponse,
                                           info=query, format="urlencoded",
                                           scope="foo bar")

        assert aresp.code == "SplxlOBeZQQYbYS6WxAAAA"
        assert aresp.state == "klm"

        assert self.client.grant["foo bar"]
        assert self.client.grant["foo bar"].code == aresp.code
        assert self.client.grant["foo bar"].grant_expiration_time

        assert _eq(self.client.grant.keys(), ['', 'foo bar', 'foo'])

    def test_parse_authz_resp_query_unknown_parameter(self):
        query = "code=SplxlOBeZQQYbYS6WxSbIA&state=xyz&foo=bar"
        aresp = self.client.parse_response(oauth2.AuthorizationResponse,
                                           info=query, format="urlencoded",
                                           scope="bar")

        assert aresp.code == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp.state == "xyz"

        print aresp.__dict__.keys()
        assert "foo" not in aresp.__dict__
        
        assert self.client.grant["bar"]
        assert self.client.grant["bar"].code == aresp.code
        assert self.client.grant["bar"].grant_expiration_time

    def test_get_access_token_request_1(self):
        self.client.reset()
        self.client.redirect_uri = "http://client.example.com/authz"
        grant = oauth2.Grant()
        grant.code = "AbCdEf"
        grant.grant_expiration_time = time_util.time_sans_frac() + 30
        self.client.grant = {"": grant}

        # scope is default=""
        atr = self.client.construct_AccessTokenRequest()

        assert atr.grant_type == "authorization_code"
        assert atr.code == "AbCdEf"
        assert atr.redirect_uri == "http://client.example.com/authz"

    def test_construct_access_token_request_fail(self):
        raises(Exception,
               'self.client.construct_AccessTokenRequest(scope="unknown")')
        raises(Exception,
            'self.client.construct_AccessTokenRequest(scope="xyz",state="unknown")')

    def test_get_access_token_request_override(self):
        self.client.reset()
        self.client.redirect_uri = "http://client.example.com/authz"
        grant = oauth2.Grant()
        grant.code = "AbCdEf"
        grant.grant_expiration_time = time_util.time_sans_frac() + 30
        self.client.grant = {"xyz": grant}

        atr = self.client.construct_AccessTokenRequest(scope="xyz")

        assert atr.grant_type == "authorization_code"
        assert atr.code == "AbCdEf"
        assert atr.redirect_uri == "http://client.example.com/authz"

    def test_construct_request_no_input(self):
        self.client.response_type = ["code"]
        atr = self.client.construct_AuthorizationRequest()

        print atr
        assert atr.redirect_uri == "http://client.example.com/authz"
        assert atr.response_type == ["code"]
        assert atr.client_id == "1"

    def test_parse_access_token_response(self):
        jso = """{
       "access_token":"2YotnFZFEjr1zCsicMWpAA",
       "token_type":"example",
       "expires_in":3600,
       "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
       "example_parameter":"example_value"
     }"""

        self.client.parse_response(oauth2.AccessTokenResponse,
                                        info="".join([
                                            x.strip() for x in jso.split("\n")]))

        assert self.client.grant
        _grant = self.client.grant[""]
        assert _grant.access_token == "2YotnFZFEjr1zCsicMWpAA"
        assert _grant.token_type == "example"
        assert _grant.expires_in == 3600
        assert _grant.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"
        # I'm dropping parameters I don't recognize
        assert "example_parameter" not in self.client.__dict__

        assert self.client.access_token_is_valid()

    def test_get_access_token_refresh_1(self):
        print self.client.grant

        self.client.grant[""].grant_expiration_time = time.time()+60
        self.client.grant[""].code = "access_code"
        # Uses refresh_token from previous response
        atr = self.client.construct_RefreshAccessTokenRequest()

        assert isinstance(atr, oauth2.RefreshAccessTokenRequest)
        assert atr.grant_type == "refresh_token"
        assert atr.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"

    def test_get_access_token_refresh_2(self):
        self.client.grant["foo"] = oauth2.Grant("init")
        self.client.grant["foo"].grant_expiration_time = time.time()+60
        self.client.grant["foo"].refresh_token = "KIA"
        # Uses refresh_token from previous response
        atr = self.client.construct_RefreshAccessTokenRequest(state="init")

        assert isinstance(atr, oauth2.RefreshAccessTokenRequest)
        assert atr.grant_type == "refresh_token"
        assert atr.refresh_token == "KIA"

    def test_parse_authz_err_response(self):
        ruri = "https://client.example.com/cb?error=access_denied&amp;state=xyz"

        resp = self.client.parse_response(oauth2.AuthorizationResponse,
                                            info=ruri, format="urlencoded")

        print type(resp), resp
        assert isinstance(resp, oauth2.ErrorResponse)

        assert resp.error == "access_denied"
        assert resp.state == "xyz"

    def test_return_non_existant_grant(self):
        assert self.client.grant_from_state("123456abcdef") is None

    def test_construct_request_with_extra_args(self):
        req = self.client.construct_AccessTokenRequest(extra_args={"foo":"bar"})

        assert req
        print req.keys()
        assert _eq(req.keys(), ['code', 'grant_type', 'client_id',
                                'redirect_uri', 'foo'])
        assert req.foo == "bar"

    def test_construct_TokenRevocationRequest(self):
        req = self.client.construct_TokenRevocationRequest()

        assert req
        print req.keys()
        assert _eq(req.keys(), ['token'])
        assert req.token == "2YotnFZFEjr1zCsicMWpAA"

    def test_request_info_simple(self):
        self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(oauth2.AuthorizationRequest)

        # default == "POST"
        assert uri == 'https://example.com/authz'
        assert body == "redirect_uri=http%3A%2F%2Fclient.example.com%2Fauthz&response_type=code&client_id=1"
        assert h_args == {'headers': {'content-type': 'application/x-www-form-urlencoded'}}
        assert isinstance(cis, oauth2.AuthorizationRequest)

    def test_request_info_simple_get(self):
        #self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(
                                                    oauth2.AuthorizationRequest,
                                                    method="GET")

        assert uri == 'https://example.com/authz?redirect_uri=http%3A%2F%2Fclient.example.com%2Fauthz&response_type=code&client_id=1'
        assert body is None
        assert h_args == {}
        assert isinstance(cis, oauth2.AuthorizationRequest)

    def test_request_info_simple_get_with_req_args(self):
        #self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(
                                                    oauth2.AuthorizationRequest,
                                                    method="GET",
                                                    request_args={"state":"init"})

        print uri
        assert uri == 'https://example.com/authz?state=init&redirect_uri=http%3A%2F%2Fclient.example.com%2Fauthz&response_type=code&client_id=1'
        assert body is None
        assert h_args == {}
        assert isinstance(cis, oauth2.AuthorizationRequest)

    def test_request_info_simple_get_with_extra_args(self):
        #self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(
                                                    oauth2.AuthorizationRequest,
                                                    method="GET",
                                                    extra_args={"rock":"little"})

        print uri
        assert uri == 'https://example.com/authz?redirect_uri=http%3A%2F%2Fclient.example.com%2Fauthz&response_type=code&client_id=1&rock=little'
        assert body is None
        assert h_args == {}
        assert isinstance(cis, oauth2.AuthorizationRequest)

    def test_request_info_with_req_and_extra_args(self):
        #self.client.authorization_endpoint = "https://example.com/authz"
        uri, body, h_args, cis = self.client.request_info(
                                                oauth2.AuthorizationRequest,
                                                method="GET",
                                                request_args={"state":"init"},
                                                extra_args={"rock":"little"})

        print uri
        assert uri == 'https://example.com/authz?state=init&redirect_uri=http%3A%2F%2Fclient.example.com%2Fauthz&response_type=code&client_id=1&rock=little'
        assert body is None
        assert h_args == {}
        assert isinstance(cis, oauth2.AuthorizationRequest)

def test_get_authorization_request():
    client = oauth2.Client()
    client.redirect_uri = "https://www.example.com/authz"
    client.client_id = "a1b2c3"
    args = {"response_type":["code"]}
    ar = client.construct_AuthorizationRequest(request_args=args)
    assert ar.client_id == 'a1b2c3'
    assert ar.redirect_uri == 'https://www.example.com/authz'
    assert ar.response_type == ['code']

    client = oauth2.Client()
    client.client_id = "a1b2c3"
    args = {"response_type":["code"],
            "redirect_uri": "https://www.example.com/authz"}
    ar = client.construct_AuthorizationRequest(request_args=args)
    assert ar.client_id == 'a1b2c3'
    assert ar.redirect_uri == 'https://www.example.com/authz'
    assert ar.response_type == ['code']

def test_get_access_token_request():
    resp = oauth2.AuthorizationResponse("code", "state")
    grant = oauth2.Grant("openid", 1)
    grant.add_code(resp)

    client = oauth2.Client()
    client.grant["openid"] = grant
    time.sleep(2)
    raises(oauth2.GrantExpired,
        'client.construct_AccessTokenRequest(scope="openid")')


def test_parse_access_token_response():
    client = oauth2.Client()

    at = oauth2.AccessTokenResponse("SlAV32hkKG", "8xLOxBtZp8", 3600)
    atj = at.get_json()

    ATR = oauth2.AccessTokenResponse
    atr = client.parse_response(ATR, info=atj)

    assert _eq(atr.keys(), ['access_token', 'expires_in', 'token_type'])

    uec = at.get_urlencoded()
    raises(ValueError, 'client.parse_response(ATR, info=uec)')

    uatr = client.parse_response(ATR, info=uec, format="urlencoded")
    assert _eq(uatr.keys(), ['access_token', 'expires_in', 'token_type'])

    huec = "%s?%s" % ("https://example.com/token", uec)

    uatr = client.parse_response(ATR, info=huec, format="urlencoded")
    assert _eq(uatr.keys(), ['access_token', 'expires_in', 'token_type'])

    err = oauth2.ErrorResponse("invalid_request",
                                "Something was missing",
                                "http://example.com/error_message.html")

    jerr = err.get_json()
    uerr = err.get_urlencoded()

    _ = client.parse_response(ATR, info=jerr)
    _ = client.parse_response(ATR, info=uerr, format="urlencoded")

    raises(Exception,
           'client.parse_response(ATR, info=jerr, format="urlencoded")')

    raises(Exception, "client.parse_response(ATR, info=uerr)")

    raises(Exception,
           'client.parse_response(ATR, info=jerr, format="focus")')

#noinspection PyUnusedLocal
def test_parse_access_token_response_missing_attribute():
    at = oauth2.AccessTokenResponse("SlAV32hkKG", "8xLOxBtZp8", 3600)
    atdict = at.dictionary()
    del atdict["access_token"]
    atj = json.dumps(atdict)
    print atj
    client = oauth2.Client()
    ATR = oauth2.AccessTokenResponse

    raises(ValueError, "client.parse_response(ATR, info=atj)")

    atuec = urllib.urlencode(atdict)

    raises(ValueError,
           "client.parse_response(ATR, info=atuec, format='urlencoded')")


def test_scope_from_state():
    resp = oauth2.AuthorizationResponse("code", "state")
    grant = oauth2.Grant("state", 1)
    grant.add_code(resp)

    client = oauth2.Client()
    client.grant["openid"] = grant

    scope = client.scope_from_state("state")

    assert scope == "openid"
