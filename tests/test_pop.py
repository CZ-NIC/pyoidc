from oic.extension.message import TokenIntrospectionResponse
from oic.extension.pop import PoPClient, PoPRS, PoPAS
from oic.oauth2 import AccessTokenRequest
from oic.oauth2 import AccessTokenResponse

__author__ = 'roland'


def test_flow():
    cli = PoPClient()

    # Client creates access token request
    atreq = AccessTokenRequest(
        grant_type="authorization_code", code="SplxlOBeZQQYbYS6WxSbIA",
        redirect_uri="https://client.example.com/cb")

    # adds key information, also connects the new key to the state value used
    atreq = cli.update(atreq, 'state')

    assert 'key' in atreq

    # This is the access_token created by the AS
    access_token = "2YotnFZFEjr1zCsicMWpAA"

    pas = PoPAS()
    # Bind the key to the access token
    # This is not the way it should/will be done, the access token will be
    # a JWT with key included
    pas.token2key[access_token] = atreq['key']

    # The AS constructs the access token response
    atrsp = AccessTokenResponse(access_token=access_token,
                                token_type="bearer", state='state')

    # The client receives the response and connects the key to the access token
    cli.handle_access_token_response(atrsp)

    assert access_token in cli.token2key
    assert cli.token2key[access_token] == cli.state2key['state']

    # Time for the client to access the Resource Server
    url = 'https://example.com/rs?foo=bar&format=json'
    headers = {'Content-type': 'application/www-form-encoded'}
    body = 'access_token={}'.format(access_token)

    # creates the POP token using signed HTTP request
    pop_token = cli.auth_token('POST', atrsp['access_token'], url, headers,
                               body)
    assert pop_token
    assert len(pop_token.split('.')) == 3  # simple JWS check

    # now to the RS
    rs = PoPRS()

    # The AS constructs the token introspection response
    tir = TokenIntrospectionResponse(active=True)
    # adds key information
    tir = pas.update(tir, access_token)

    # The RS binds the received key to the access token
    rs.store_key(access_token, tir)

    # The RS verifies the correctness of the POP token
    res = rs.eval_signed_http_request(pop_token, access_token, 'POST',
                                      url, headers, body)

    # YEY :-)
    assert res
