__author__ = 'rohe0002'

from oic import oic
from oic.oic import Client
from oic.oic import Server
from oic.utils import time_util
from oic import oauth2

def _eq(l1, l2):
    return set(l1) == set(l2)


class TestOICClient():
    def setup_class(self):
        self.client = Client("1")
        self.client.redirect_uri = "http://example.com/redirect"

    def test_areq_1(self):
        args = {"response_type":["code"]}
        ar = self.client.construct_AuthorizationRequest(request_args=args)

        assert ar.redirect_uri == "http://example.com/redirect"
        assert ar.response_type == ["code"]
        assert ar.client_id == "1"
        assert ar.state is None
        assert ar.scope == []

    def test_areq_2(self):
        self.client.state = "xyz"
        args = {"response_type":["code"], "scope":["foo", "bar"]}
        ar = self.client.construct_AuthorizationRequest(request_args=args)

        assert ar.redirect_uri == "http://example.com/redirect"
        assert ar.response_type == ["code"]
        assert ar.client_id == "1"
        assert ar.state == "xyz"
        assert ar.scope == ["foo", "bar"]

    def test_areq_replace_default_state(self):
        self.client.state = "xyz"
        args = {"response_type":["code"], "scope":["foo", "bar"], "state":"fox"}
        ar = self.client.construct_AuthorizationRequest(request_args=args)

        assert ar.redirect_uri == "http://example.com/redirect"
        assert ar.response_type == ["code"]
        assert ar.client_id == "1"
        assert ar.state == "fox"
        assert ar.scope == ["foo", "bar"]

    def test_parse_authz_resp_url(self):
        url = "https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz"
        aresp = self.client.parse_response(oic.AuthorizationResponse,
                                           info=url, format="urlencoded")

        assert aresp.code == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp.state == "xyz"

        assert self.client.grant["xyz"]
        assert self.client.grant["xyz"].code == aresp.code
        assert self.client.grant["xyz"].grant_expiration_time

    def test_parse_authz_resp_query(self):
        query = "code=SplxlOBeZQQYbYS6WxSbIA&state=abc"
        aresp = self.client.parse_response(oic.AuthorizationResponse,
                                           info=query, format="urlencoded")

        assert aresp.code == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp.state == "abc"

        assert self.client.grant["abc"]
        assert self.client.grant["abc"].code == aresp.code
        assert self.client.grant["abc"].grant_expiration_time

    def test_parse_authz_resp_query_unknown_parameter(self):
        query = "code=SplxlOBeZQQYbYS6WxSbIA&state=rst&foo=bar"
        aresp = self.client.parse_response(oic.AuthorizationResponse,
                                           info=query, format="urlencoded")

        assert aresp.code == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp.state == "rst"

        print aresp.__dict__.keys()
        assert "foo" not in aresp.__dict__

        assert self.client.grant["rst"]
        assert self.client.grant["rst"].code == aresp.code
        assert self.client.grant["rst"].grant_expiration_time

    def test_get_access_token_request_1(self):
        self.client.reset()
        self.client.redirect_uri = "http://client.example.com/authz"
        grant = oauth2.Grant()
        grant.code = "AbCdEf"
        grant.grant_expiration_time = time_util.time_sans_frac() + 30
        self.client.grant = {"openid": grant}

        # scope is default=""
        atr = self.client.construct_AccessTokenRequest(state="openid")

        assert atr.grant_type == "authorization_code"
        assert atr.code == "AbCdEf"
        assert atr.redirect_uri == "http://client.example.com/authz"

    def test_get_access_token_request_override(self):
        self.client.reset()
        self.client.redirect_uri = "http://client.example.com/authz"
        grant = oauth2.Grant()
        grant.code = "AbCdEf"
        grant.grant_expiration_time = time_util.time_sans_frac() + 30
        self.client.grant = {"xyz": grant}

        atr = self.client.construct_AccessTokenRequest(state="xyz")

        assert atr.grant_type == "authorization_code"
        assert atr.code == "AbCdEf"
        assert atr.redirect_uri == "http://client.example.com/authz"

    def test_parse_access_token_response(self):
        jso = """{
       "access_token":"2YotnFZFEjr1zCsicMWpAA",
       "token_type":"example",
       "expires_in":3600,
       "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
       "example_parameter":"example_value"
     }"""

        self.client.parse_response(oic.AccessTokenResponse,
                                    info="".join(
                                        [x.strip() for x in jso.split("\n")]))

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

        assert token.is_valid()

#    def test_get_access_token_refresh_1(self):
#        # Uses refresh_token from previous response
#        atr = self.client.get_access_token_refresh()
#
#        assert isinstance(atr, oauth2.RefreshAccessTokenRequest)
#        assert atr.grant_type == "refresh_token"
#        assert atr.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"
#
#
#    def test_parse_authz_err_response(self):
#        ruri = "https://client.example.com/cb?error=access_denied&amp;state=xyz"
#
#        resp = self.client.parse_authorization_response(url=ruri)
#
#        assert isinstance(resp, oauth2.AuthorizationErrorResponse)
#
#        assert resp.error == "access_denied"
#        assert resp.state == "xyz"
#
#
#    def test_parse_authz_response_2(self):
#        ruri = "nonce=rld7t7eXH7GR&code=enAPFuUhruD7AkUB0PKS%2F66XFJEtgOmWuKPpmTcG4ag%3D&state=2aa45025b0578eddcfcdf979b4f344b7&scope=openid"
#        resp = self.client.parse_authorization_response(query=ruri)
#
#        assert isinstance(resp, oic.AuthorizationResponse)
#
#        assert resp.nonce == "rld7t7eXH7GR"
#        assert resp.state == "2aa45025b0578eddcfcdf979b4f344b7"
#        assert resp.scope == ["openid"]
#
#    def test_get_authorization_request_with_request(self):
#        self.client.key="a1b2c3d4"
#        self.client.algorithm = "HS256"
#
#        arr = self.client.get_authorization_request_with_request(
#            response_type=["code"],
#            scope=["openid"],
#            state="xyz012"
#        )
#
#        print arr
#        assert arr
#        assert arr.request
