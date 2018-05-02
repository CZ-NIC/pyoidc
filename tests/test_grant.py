# pylint: disable=missing-docstring,no-self-use
from oic.oauth2.grant import Grant
from oic.oauth2.grant import Token
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import ErrorResponse

ATR = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                          token_type="example",
                          refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                          example_parameter="example_value",
                          scope=["inner", "outer"])
AR = AuthorizationResponse(code="code", state="state")


def _eq(l1, l2):
    return set(l1) == set(l2)


class TestGrant(object):
    def test_expiration_time(self):
        grant = Grant()
        assert grant.exp_in == 600
        assert grant.grant_expiration_time == 0

        grant = Grant(60)
        assert grant.exp_in == 60

        grant = Grant(-1, AR)
        assert grant.grant_expiration_time != 0
        assert not grant.is_valid()

    def test_from_code(self):
        grant = Grant.from_code(AR)

        assert grant.code == "code"
        assert grant.grant_expiration_time != 0

    def test_add_code(self):
        grant = Grant()
        grant.add_code(AR)
        assert grant.code == "code"

    def test_update(self):
        grant = Grant()
        grant.update(AR)

        assert grant.code == "code"

    def test_set(self):
        grant = Grant.from_code(AR)

        assert grant.code == "code"

    def test_add_token(self):
        grant = Grant()
        grant.update(ATR)

        assert len(grant.tokens) == 1
        token = grant.tokens[0]

        assert token.access_token == "2YotnFZFEjr1zCsicMWpAA"
        assert token.token_type == "example"
        assert token.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"

    def test_update_with_error_resp(self):
        err = ErrorResponse(error="invalid_request")
        grant = Grant()
        grant.update(err)

        assert len(grant.tokens) == 0

    def test_delete_token(self):
        grant = Grant()
        grant.update(ATR)

        token = grant.get_token()

        grant.delete_token(token)
        assert len(grant.tokens) == 0

    def test_delete_unknown(self):
        grant = Grant()
        grant.update(ATR)

        atr = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                                  token_type="example",
                                  refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                                  xscope=["inner", "outer"])
        token = Token(atr)

        grant.delete_token(token)
        assert len(grant.tokens) == 1


class TestToken(object):
    def test_access_token(self):
        atr = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                                  token_type="example", expires_in=-1,
                                  refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                                  example_parameter="example_value",
                                  xscope=["inner", "outer"])
        token = Token(atr)
        assert _eq(token.keys(), ['token_expiration_time', 'access_token',
                                  'expires_in', 'example_parameter',
                                  'token_type',
                                  'xscope', 'refresh_token', 'scope',
                                  'replaced'])

        assert token.access_token == "2YotnFZFEjr1zCsicMWpAA"
        assert token.token_type == "example"
        assert token.refresh_token == "tGzv3JOkF0XG5Qx2TlKWIA"
        assert token.example_parameter == "example_value"
        assert token.xscope == ["inner", "outer"]
        assert token.token_expiration_time != 0
        assert not token.is_valid()


def test_grant_access_token():
    resp = AuthorizationResponse(code="code", state="state")
    grant = Grant()
    grant.add_code(resp)

    atr = AccessTokenResponse(access_token="2YotnFZFEjr1zCsicMWpAA",
                              token_type="example",
                              refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
                              example_parameter="example_value",
                              scope=["inner", "outer"])

    grant.add_token(atr)
    assert len(grant.tokens) == 1
    token = grant.tokens[0]
    assert token.is_valid() is True

    assert str(grant) != ""
