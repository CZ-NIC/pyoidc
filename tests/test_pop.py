from oic.extension.message import TokenIntrospectionResponse
from oic.extension.pop import PoPClient, PoPRS, PoPAS
from oic.oauth2 import AccessTokenRequest
from oic.oauth2 import AccessTokenResponse

__author__ = 'roland'


def test_flow():
    cli = PoPClient()

    atreq = AccessTokenRequest(
        grant_type="authorization_code", code="SplxlOBeZQQYbYS6WxSbIA",
        redirect_uri="https://client.example.com/cb")

    atreq = cli.update(atreq, 'state')

    assert 'key' in atreq

    access_token = "2YotnFZFEjr1zCsicMWpAA"

    pas = PoPAS()
    pas.token2key[access_token] = atreq['key']

    atrsp = AccessTokenResponse(access_token=access_token,
                                token_type="bearer", state='state')

    cli.handle_access_token_response(atrsp)

    assert access_token in cli.token2key
    assert cli.token2key[access_token] == cli.state2key['state']

    url = 'https://example.com/rs?foo=bar&format=json'
    headers = {'Content-type': 'application/www-form-encoded'}

    pop_token = cli.auth_token('POST', atrsp['access_token'], url, headers)
    assert pop_token
    assert len(pop_token.split('.')) == 3  # simple JWS check

    rs = PoPRS()

    tir = TokenIntrospectionResponse(active=True)
    tir = pas.update(tir, access_token)

    rs.store_key(access_token, tir)

    res = rs.eval_signed_http_request(pop_token, access_token, 'POST',
                                      url, headers)

    assert res