#!/usr/bin/env python

__author__ = 'rohe0002'

from oic import oauth2
import time

class TestClient():
    def setup_class(self):
        self.client = oauth2.Client("1")
        self.client.redirect_uri = "http://example.com/redirect"

    def test_areq_1(self):
        ar = self.client.get_authorization_request(response_type=["code"])

        assert ar.redirect_uri == "http://example.com/redirect"
        assert ar.response_type == ["code"]
        assert ar.client_id == "1"
        assert ar.state is None
        assert ar.scope == []
        
    def test_areq_2(self):
        self.client.state = "xyz"
        self.client.scope = ["foo", "bar"]
        ar = self.client.get_authorization_request(response_type=["code"])

        assert ar.redirect_uri == "http://example.com/redirect"
        assert ar.response_type == ["code"]
        assert ar.client_id == "1"
        assert ar.state == "xyz"
        assert ar.scope == ["foo", "bar"]

    def test_areq_replace_default_state(self):
        self.client.state = "xyz"
        self.client.scope = ["foo", "bar"]
        ar = self.client.get_authorization_request(response_type=["code"])

        assert ar.redirect_uri == "http://example.com/redirect"
        assert ar.response_type == ["code"]
        assert ar.client_id == "1"
        assert ar.state == "xyz"
        assert ar.scope == ["foo", "bar"]

    def test_parse_authz_resp_url(self):
        url = "https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz"
        aresp = self.client.parse_authorization_response(url=url)

        assert aresp.code == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp.state == "xyz"
        
        assert self.client.authorization_code == "SplxlOBeZQQYbYS6WxSbIA"
        assert self.client.grant_expiration_time != 0

    def test_parse_authz_resp_query(self):
        query = "code=SplxlOBeZQQYbYS6WxSbIA&state=xyz"
        aresp = self.client.parse_authorization_response(query=query)

        assert aresp.code == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp.state == "xyz"

        assert self.client.authorization_code == "SplxlOBeZQQYbYS6WxSbIA"
        assert self.client.grant_expiration_time != 0

    def test_parse_authz_resp_query_unknown_parameter(self):
        query = "code=SplxlOBeZQQYbYS6WxSbIA&state=xyz&foo=bar"
        aresp = self.client.parse_authorization_response(query=query)

        assert aresp.code == "SplxlOBeZQQYbYS6WxSbIA"
        assert aresp.state == "xyz"

        print aresp.__dict__.keys()
        assert "foo" not in aresp.__dict__
        
        assert self.client.authorization_code == "SplxlOBeZQQYbYS6WxSbIA"
        assert self.client.grant_expiration_time != 0

    def test_get_access_token_request_1(self):
        self.client.reset()
        self.client.redirect_uri = "http://client.example.com/authz"
        self.client.authorization_code = "AbCdEf"
        self.client.grant_expiration_time = time.time() + 30

        atr = self.client.get_access_token_request()

        assert atr.grant_type == "authorization_code"
        assert atr.code == "AbCdEf"
        assert atr.redirect_uri == "http://client.example.com/authz"

    def test_get_access_token_request_override(self):
        self.client.reset()
        self.client.redirect_uri = "http://client.example.com/authz"
        self.client.authorization_code = "AbCdEf"
        self.client.grant_expiration_time = time.time() + 30

        atr = self.client.get_access_token_request()

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

        self.client.parse_access_token_response(info="".join([
                                        x.strip() for x in jso.split("\n")]))

        assert self.client.access_token
        assert self.client.access_token.access_token == "2YotnFZFEjr1zCsicMWpAA"
        assert self.client.access_token.token_type == "example"
        assert self.client.access_token.expires_in == 3600
        assert self.client.access_token.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"
        # I'm dropping parameters I don't recognize
        assert "example_parameter" not in self.client.access_token.__dict__

    def test_get_access_token_refresh_1(self):
        # Uses refresh_token from previous response
        atr = self.client.get_access_token_refresh(scope="/foo/bar")

        assert isinstance(atr, oauth2.RefreshAccessTokenRequest)
        assert atr.grant_type == "refresh_token"
        assert atr.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"
        assert atr.scope == "/foo/bar"
        

    def test_get_authorization_request_with_request(self):
        self.client.key="a1b2c3d4"
        self.client.algorithm = "HS256"

        arr = self.client.get_authorization_request_with_request(
            response_type=["code"],
            scope=["openid"],
            state="xyz012"
        )

        print arr
        assert arr
        assert arr.request


    def test_parse_authz_err_response(self):
        ruri = "https://client.example.com/cb?error=access_denied&amp;state=xyz"

        resp = self.client.parse_authorization_response(url=ruri)

        assert isinstance(resp, oauth2.AuthorizationErrorResponse)

        assert resp.error == "access_denied"
        assert resp.state == "xyz"
        