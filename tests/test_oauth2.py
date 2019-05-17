import json
from urllib.parse import parse_qs
from urllib.parse import quote
from urllib.parse import urlencode
from urllib.parse import urlparse

import pytest

from oic.oauth2 import Client
from oic.oauth2 import Grant
from oic.oauth2 import Server
from oic.oauth2 import Token
from oic.oauth2.exception import GrantError
from oic.oauth2.exception import MissingEndpoint
from oic.oauth2.exception import ResponseError
from oic.oauth2.message import AccessTokenRequest
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import AuthorizationErrorResponse
from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import FormatError
from oic.oauth2.message import GrantExpired
from oic.oauth2.message import MissingRequiredAttribute
from oic.oauth2.message import RefreshAccessTokenRequest
from oic.utils import time_util
from oic.utils.keyio import KeyBundle

__author__ = 'rohe0002'

ACC_TOK_RESP = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                                   token_type="example",
                                   refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                                   scope=["inner", "outer"])


def url_compare(url1, url2):
    url1 = urlparse(url1)
    url2 = urlparse(url2)

    if url1.scheme != url2.scheme:
        return False
    if url1.netloc != url2.netloc:
        return False
    if url1.path != url2.path:
        return False
    if not query_string_compare(url1.query, url2.query):
        return False
    if not query_string_compare(url1.fragment, url2.fragment):
        return False

    return True


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


def _eq(l1, l2):
    return set(l1) == set(l2)


class TestClient(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        self.redirect_uri = "https://example.com/redirect"
        self.authorization_endpoint = "https://example.com/authz"

        self.client = Client("1", config={'issuer': 'https://example.com/as'})
        self.client.redirect_uris = [self.redirect_uri]
        self.client.response_type = "code"
        self.client.authorization_endpoint = self.authorization_endpoint

    def test_construct_authz_req_no_optional_params(self):
        areq = self.client.construct_AuthorizationRequest(
            request_args={"response_type": ["code"]})

        assert areq["redirect_uri"] == self.redirect_uri
        assert areq["response_type"] == ["code"]
        assert areq["client_id"] == "1"
        assert "state" not in areq
        assert "scope" not in areq

    def test_construct_authz_req_no_input(self):
        self.client.response_type = ["code"]
        atr = self.client.construct_AuthorizationRequest()

        assert atr["redirect_uri"] == self.redirect_uri
        assert atr["response_type"] == ["code"]
        assert atr["client_id"] == "1"

    def test_construct_authz_req_optional_params(self):
        req_args = {"response_type": ["code"], "scope": ["foo", "bar"],
                    "state": "abc"}
        areq = self.client.construct_AuthorizationRequest(request_args=req_args)

        assert areq["redirect_uri"] == self.redirect_uri
        assert areq["response_type"] == ["code"]
        assert areq["client_id"] == "1"
        assert areq["state"] == "abc"
        assert areq["scope"] == ["foo", "bar"]

    def test_construct_authz_req_replace_default_state(self):
        req_args = {"response_type": ["code"], "scope": ["foo", "bar"],
                    "state": "efg"}
        areq = self.client.construct_AuthorizationRequest(request_args=req_args)

        assert areq["redirect_uri"] == self.redirect_uri
        assert areq["response_type"] == ["code"]
        assert areq["client_id"] == "1"
        assert areq["state"] == "efg"
        assert areq["scope"] == ["foo", "bar"]

    def test_parse_authz_resp_url(self):
        code = "SplxlOBeZQQYbYS6WxSbIA"
        state = "ghi"
        url = "{}?code={}&state={}".format(self.redirect_uri, code, state)
        aresp = self.client.parse_response(AuthorizationResponse,
                                           info=url, sformat="urlencoded")

        assert aresp["code"] == code
        assert aresp["state"] == state

        assert self.client.grant[state].code == aresp["code"]
        assert self.client.grant[state].grant_expiration_time

    def test_parse_authz_resp_query(self):
        query = "code=SplxlOBeZQQYbYS6WxSbIA&state=hij"
        aresp = self.client.parse_response(AuthorizationResponse,
                                           info=query, sformat="urlencoded")

        assert aresp["code"] == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp["state"] == "hij"

        assert self.client.grant["hij"]
        assert self.client.grant["hij"].code == aresp["code"]
        assert self.client.grant["hij"].grant_expiration_time

    def test_parse_authz_resp_query_multi_scope(self):
        code = "SplxlOBeZQQYbYS6WxSbIA"
        states = ["ghi", "hij", "klm"]

        for state in states:
            self.client.parse_response(AuthorizationResponse,
                                       info="code={}&state={}".format(code,
                                                                      state),
                                       sformat="urlencoded")

        for state in states:
            assert self.client.grant[state].code == code

        assert _eq(self.client.grant.keys(), states)

    def test_parse_authz_resp_query_unknown_parameter(self):
        query = "code=SplxlOBeZQQYbYS6WxSbIA&state=xyz&foo=bar"
        aresp = self.client.parse_response(AuthorizationResponse,
                                           info=query, sformat="urlencoded")

        assert aresp["code"] == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp["state"] == "xyz"

        # assert "foo" not in aresp # TODO unknown parameter not discarded

        assert self.client.grant["xyz"]
        assert self.client.grant["xyz"].code == aresp["code"]
        assert self.client.grant["xyz"].grant_expiration_time

    def test_construct_access_token_req(self):
        grant = Grant()
        grant.code = "AbCdEf"
        grant.grant_expiration_time = time_util.utc_time_sans_frac() + 30
        self.client.grant = {"stat": grant}

        # scope is default=""
        atr = self.client.construct_AccessTokenRequest(state="stat")

        assert atr["grant_type"] == "authorization_code"
        assert atr["code"] == "AbCdEf"
        assert atr["redirect_uri"] == self.redirect_uri

    def test_construct_access_token_request_fail(self):
        with pytest.raises(GrantError):
            self.client.construct_AccessTokenRequest(state="unknown")

    def test_construct_access_token_req_override(self):
        grant = Grant()
        grant.code = "AbCdEf"
        grant.grant_expiration_time = time_util.utc_time_sans_frac() + 30
        self.client.grant = {"xyz": grant}

        atr = self.client.construct_AccessTokenRequest(state="xyz")

        assert atr["grant_type"] == "authorization_code"
        assert atr["code"] == "AbCdEf"
        assert atr["redirect_uri"] == self.redirect_uri

    def test_parse_access_token_resp(self):
        atr = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                                  token_type="example", expires_in=3600,
                                  refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                                  example_parameter="example_value")

        self.client.parse_response(AccessTokenResponse,
                                   info=json.dumps(atr.to_dict()))

        _grant = self.client.grant[""]
        assert len(_grant.tokens) == 1
        token = _grant.tokens[0]
        assert token.access_token == "2YotnFZFEjr1zCsicMWpAA"
        assert token.token_type == "example"
        assert token.expires_in == 3600
        assert token.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"

    def test_get_access_token_refresh_with_refresh_token(self):
        self.client.grant["foo"] = Grant()
        _get = time_util.utc_time_sans_frac() + 60
        self.client.grant["foo"].grant_expiration_time = _get
        self.client.grant["foo"].code = "access_code"
        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access")
        token = Token(resp)
        self.client.grant["foo"].tokens.append(token)

        # Uses refresh_token from previous response
        atr = self.client.construct_RefreshAccessTokenRequest(token=token)

        assert atr["grant_type"] == "refresh_token"
        assert atr["refresh_token"] == "refresh_with_me"

    def test_get_access_token_refresh_from_state(self):
        self.client.grant["foo"] = Grant()
        _get = time_util.utc_time_sans_frac() + 60
        self.client.grant["foo"].grant_expiration_time = _get
        self.client.grant["foo"].code = "access_code"

        resp = AccessTokenResponse(refresh_token="refresh_with_me",
                                   access_token="access")

        self.client.grant["foo"].tokens.append(Token(resp))
        # Uses refresh_token from previous response
        atr = self.client.construct_RefreshAccessTokenRequest(state="foo")

        assert isinstance(atr, RefreshAccessTokenRequest)
        assert atr["grant_type"] == "refresh_token"
        assert atr["refresh_token"] == "refresh_with_me"

    def test_parse_authz_err_resp(self):
        error = "access_denied"
        state = "xyz"
        ruri = "{}?error={}&state={}".format(self.redirect_uri, error, state)

        resp = self.client.parse_response(AuthorizationResponse,
                                          info=ruri, sformat="urlencoded")

        assert isinstance(resp, AuthorizationErrorResponse)
        assert resp["error"] == error
        assert resp["state"] == state

    def test_return_non_existant_grant(self):
        assert self.client.grant_from_state("123456abcdef") is None

    def test_get_grant(self):
        resp = AuthorizationResponse(code="code", state="state")
        grant = Grant()
        grant.add_code(resp)

        self.client.grant["state"] = grant
        assert self.client.grant_from_state("state").code == "code"

    def test_construct_access_token_req_with_extra_args(self):
        query = "code=SplxlOBeZQQYbYS6WxSbIA&state=abc"
        self.client.parse_response(AuthorizationResponse,
                                   info=query, sformat="urlencoded")

        req = self.client.construct_AccessTokenRequest(state="abc",
                                                       extra_args={
                                                           "foo": "bar"})

        assert _eq(req.keys(), ["code", "grant_type", "client_id",
                                "redirect_uri", "foo", 'state'])
        assert req["foo"] == "bar"

    def test_request_info_simple(self):
        req_args = {"state": "hmm", "response_type": "code"}
        uri, body, h_args, cis = self.client.request_info(AuthorizationRequest,
                                                          request_args=req_args)

        assert uri == self.authorization_endpoint
        body_elts = body.split('&')
        expected_body = "state=hmm&redirect_uri={}&response_type=code&client_id=1".format(
            quote(self.redirect_uri, safe=""))
        expected_body_elts = expected_body.split('&')
        assert set(body_elts) == set(expected_body_elts)
        assert h_args == {
            'headers': {'Content-Type': 'application/x-www-form-urlencoded'}}
        assert isinstance(cis, AuthorizationRequest)

    def test_request_info_simple_get(self):
        uri, body, h_args, cis = self.client.request_info(AuthorizationRequest,
                                                          method="GET")
        assert url_compare(uri,
                           '{}?redirect_uri={}&response_type=code&client_id=1'.format(
                               self.authorization_endpoint,
                               quote(self.redirect_uri, safe="")))
        assert body is None
        assert h_args == {}

    def test_request_info_simple_get_with_req_args(self):
        uri, body, h_args, cis = self.client.request_info(
            AuthorizationRequest, method="GET", request_args={"state": "init"})

        assert url_compare(uri,
                           '{}?state=init&redirect_uri={}&response_type=code&client_id=1'.format(
                               self.authorization_endpoint,
                               quote(self.redirect_uri, safe="")))
        assert body is None
        assert h_args == {}
        assert isinstance(cis, AuthorizationRequest)

    def test_request_info_simple_get_with_extra_args(self):
        uri, body, h_args, cis = self.client.request_info(
            AuthorizationRequest, method="GET", extra_args={"rock": "little"})

        assert url_compare(uri,
                           '{}?redirect_uri={}&response_type=code&client_id=1&rock=little'.format(
                               self.authorization_endpoint,
                               quote(self.redirect_uri, safe="")))
        assert body is None
        assert h_args == {}
        assert isinstance(cis, AuthorizationRequest)

    def test_request_info_with_req_and_extra_args(self):
        uri, body, h_args, cis = self.client.request_info(
            AuthorizationRequest,
            method="GET",
            request_args={"state": "init"},
            extra_args={"rock": "little"})

        expected = '{}?state=init&redirect_uri={}&response_type=code&client_id=1&rock=little'
        assert url_compare(uri, expected.format(self.authorization_endpoint,
                                                quote(self.redirect_uri,
                                                      safe="")))
        assert body is None
        assert h_args == {}
        assert isinstance(cis, AuthorizationRequest)

    def test_construct_access_token_req_expired_grant(self):
        resp = AuthorizationResponse(code="code", state="state")
        grant = Grant(-10)  # expired grant
        grant.add_code(resp)

        client = Client()
        client.grant["openid"] = grant
        with pytest.raises(GrantExpired):
            client.construct_AccessTokenRequest(state="openid")

    def test_parse_access_token_resp_json(self):
        atr = self.client.parse_response(AccessTokenResponse,
                                         info=ACC_TOK_RESP.to_json())
        assert _eq(atr.keys(),
                   ['token_type', 'scope', 'access_token', 'refresh_token'])

    def test_parse_access_token_resp_urlencoded(self):
        uatr = self.client.parse_response(AccessTokenResponse,
                                          info=ACC_TOK_RESP.to_urlencoded(),
                                          sformat="urlencoded")
        assert _eq(uatr.keys(),
                   ['token_type', 'scope', 'access_token', 'refresh_token'])

    def test_parse_access_token_resp_url(self):
        url = "{}?{}".format("https://example.com/token",
                             ACC_TOK_RESP.to_urlencoded())
        uatr = self.client.parse_response(AccessTokenResponse, info=url,
                                          sformat="urlencoded")
        assert _eq(uatr.keys(),
                   ['token_type', 'scope', 'access_token', 'refresh_token'])

    def test_parse_error_resp(self):
        err = ErrorResponse(error="invalid_request",
                            error_description="Something was missing",
                            error_uri="http://example.com/error_message.html")
        jerr = err.to_json()
        uerr = err.to_urlencoded()

        self.client.parse_response(AccessTokenResponse, info=jerr)
        self.client.parse_response(AccessTokenResponse, info=uerr,
                                   sformat="urlencoded")

        with pytest.raises(ResponseError):
            self.client.parse_response(AccessTokenResponse, info=jerr, sformat="urlencoded")

        with pytest.raises(ValueError):
            self.client.parse_response(AccessTokenResponse, info=uerr)

        with pytest.raises(FormatError):
            self.client.parse_response(AccessTokenResponse, info=jerr, sformat="focus")

    def test_parse_access_token_resp_missing_attribute(self):
        atresp = AccessTokenResponse(access_token="SlAV32hkKG",
                                     token_type="Bearer",
                                     refresh_token="8xLOxBtZp8",
                                     expire_in=3600)
        atdict = atresp.to_dict()
        del atdict["access_token"]  # remove required access_token
        atj = json.dumps(atdict)

        with pytest.raises(MissingRequiredAttribute):
            self.client.parse_response(AccessTokenResponse, info=atj)

        with pytest.raises(MissingRequiredAttribute):
            self.client.parse_response(AccessTokenResponse,
                                       info=urlencode(atdict),
                                       sformat='urlencoded')

    def test_client_parse_args(self):
        args = {
            "response_type": "",
            "client_id": "client_id",
            "redirect_uri": "http://example.com/authz",
            "scope": "scope",
            "state": "state",
        }

        ar_args = self.client._parse_args(AuthorizationRequest, **args)

        assert _eq(ar_args.keys(), ['scope', 'state', 'redirect_uri',
                                    'response_type', 'client_id'])

    def test_client_parse_extra_args(self):
        args = {
            "response_type": "",
            "client_id": "client_id",
            "redirect_uri": "http://example.com/authz",
            "scope": "scope",
            "state": "state",
            "extra_session": "home"
        }
        ar_args = self.client._parse_args(AuthorizationRequest, **args)

        assert _eq(ar_args.keys(), ['state', 'redirect_uri', 'response_type',
                                    'client_id', 'scope', 'extra_session'])

    def test_client_endpoint(self):
        self.client.authorization_endpoint = "https://example.org/oauth2/as"
        self.client.token_endpoint = "https://example.org/oauth2/token"
        self.client.token_revocation_endpoint = "https://example.org/oauth2/token_rev"

        assert self.client._endpoint(
            "authorization_endpoint") == "https://example.org/oauth2/as"
        assert self.client._endpoint(
            "token_endpoint") == "https://example.org/oauth2/token"
        assert self.client._endpoint(
            "token_revocation_endpoint") == "https://example.org/oauth2/token_rev"

        auth_endpoint = self.client._endpoint("authorization_endpoint", **{
            "authorization_endpoint": "https://example.com/as"})
        assert auth_endpoint == "https://example.com/as"

        self.client.token_endpoint = ""
        with pytest.raises(MissingEndpoint):
            self.client._endpoint("token_endpoint")
            self.client._endpoint("foo_endpoint")


class TestServer(object):
    @pytest.fixture(autouse=True)
    def create_server(self):
        self.srv = Server()  # pylint: disable=attribute-defined-outside-init

    def test_parse_authz_req(self):
        ar = AuthorizationRequest(response_type=["code"],
                                  client_id="foobar",
                                  redirect_uri="http://foobar.example.com/oaclient",
                                  state="cold")

        uencq = ar.to_urlencoded()

        areq = self.srv.parse_authorization_request(query=uencq)

        assert isinstance(areq, AuthorizationRequest)
        assert areq["response_type"] == ["code"]
        assert areq["client_id"] == "foobar"
        assert areq["redirect_uri"] == "http://foobar.example.com/oaclient"
        assert areq["state"] == "cold"

        urluenc = "%s?%s" % ("https://example.com/authz", uencq)
        areq = self.srv.parse_authorization_request(url=urluenc)

        assert isinstance(areq, AuthorizationRequest)
        assert areq["response_type"] == ["code"]
        assert areq["client_id"] == "foobar"
        assert areq["redirect_uri"] == "http://foobar.example.com/oaclient"
        assert areq["state"] == "cold"

    def test_parse_jwt_request(self):
        ar = AuthorizationRequest(response_type=["code"],
                                  client_id="foobar",
                                  redirect_uri="http://foobar.example.com/oaclient",
                                  state="cold")

        self.srv.keyjar["foobar"] = KeyBundle([
            {"kty": "oct", "key": "A1B2C3D4".encode("utf-8"), "use": "ver"},
            {"kty": "oct", "key": "A1B2C3D4".encode("utf-8"), "use": "sig"}])
        self.srv.keyjar[""] = KeyBundle([
            {"kty": "oct", "key": "A1B2C3D4".encode("utf-8"), "use": "ver"},
            {"kty": "oct", "key": "A1B2C3D4".encode("utf-8"), "use": "sig"}])

        keys = self.srv.keyjar.get_signing_key(owner="foobar")
        _jwt = ar.to_jwt(key=keys, algorithm="HS256")

        req = self.srv.parse_jwt_request(txt=_jwt)

        assert isinstance(req, AuthorizationRequest)
        assert req["response_type"] == ["code"]
        assert req["client_id"] == "foobar"
        assert req["redirect_uri"] == "http://foobar.example.com/oaclient"
        assert req["state"] == "cold"

    def test_server_parse_token_request(self):
        atr = AccessTokenRequest(
            grant_type="authorization_code", code="SplxlOBeZQQYbYS6WxSbIA",
            redirect_uri="https://client.example.com/cb", extra="foo")
        uenc = atr.to_urlencoded()

        tr = self.srv.parse_token_request(body=uenc)

        assert isinstance(tr, AccessTokenRequest)
        assert _eq(tr.keys(), ['code', 'redirect_uri', 'grant_type', 'extra'])

        assert tr["grant_type"] == "authorization_code"
        assert tr["code"] == "SplxlOBeZQQYbYS6WxSbIA"

        tr = self.srv.parse_token_request(body=uenc)

        assert isinstance(tr, AccessTokenRequest)
        assert _eq(tr.keys(), ['code', 'grant_type', 'redirect_uri', 'extra'])

        assert tr["extra"] == "foo"

    def test_server_parse_refresh_token_request(self):
        ratr = RefreshAccessTokenRequest(refresh_token="ababababab",
                                         client_id="Client_id")
        uenc = ratr.to_urlencoded()

        tr = self.srv.parse_refresh_token_request(body=uenc)

        assert isinstance(tr, RefreshAccessTokenRequest)
        assert tr["refresh_token"] == "ababababab"
        assert tr["client_id"] == "Client_id"
