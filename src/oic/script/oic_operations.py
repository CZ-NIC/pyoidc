__author__ = 'rohe0002'

from oic.script.opfunc import *

# ========================================================================

RESPOND = {
    "method": "POST",
    }

AUTHZREQ_CODE = {
    "request": "AuthorizationRequest",
    "method": "GET",
    "args": {
        "request": {"response_type": "code", "scope": ["openid"]},
    }
}

AUTHZRESP = {
    "response": "AuthorizationResponse",
    "where": "url",
    "type": "urlencoded",
}

ACCESS_TOKEN_RESPONSE = {
    "response": "AccessTokenResponse",
    "where": "body",
    "type": "json"
}

USER_INFO_RESPONSE = {
    "response": "OpenIDSchema",
    "where": "body",
    "type": "json"
}

ACCESS_TOKEN_REQUEST_PASSWD = {
    "request":"AccessTokenRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "client_secret_basic"}
    },
}

ACCESS_TOKEN_REQUEST_CLI_SECRET = {
    "request":"AccessTokenRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "client_secret_post"}
    },
}

USER_INFO_REQUEST = {
    "request":"UserInfoRequest",
    "method": "POST",
    "args": {
        "kw": {"token_placement": "header"}
    },
}

USER_INFO_REQUEST_BODY = {
    "request":"UserInfoRequest",
    "method": "POST",
    "args": {
        "kw": {"token_placement": "body"}
    },
}

PROVIDER_CONFIGURATION = {
    "request": "ProviderConfigurationRequest"
}

CHECK_ID_REQUEST = {
    "request": "CheckIDRequest",
    "method": "POST"
}

CHECK_ID_RESPONSE = {
    "response": "IdToken",
    "where": "body",
    "type": "json"
}

PHASES= {
    "login": ([AUTHZREQ_CODE], AUTHZRESP),
    "login-form": ([AUTHZREQ_CODE, LOGIN_FORM], AUTHZRESP),
    "login-form-approve": ([AUTHZREQ_CODE, LOGIN_FORM, APPROVE_FORM],
                            AUTHZRESP),
    "access-token-request":([ACCESS_TOKEN_REQUEST_CLI_SECRET],
                            ACCESS_TOKEN_RESPONSE),
    "check-id-request":([CHECK_ID_REQUEST], CHECK_ID_RESPONSE),
    "user-info-request":([USER_INFO_REQUEST_BODY], USER_INFO_RESPONSE)
}


FLOWS = {
    'basic-code-authn': {
        "name": 'Basic Code flow with authentication',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an ID Token.'),
        "sequence": ["login-form-approve"],
        "endpoints": ["authorization_endpoint"]
    },
    'basic-code-idtoken': {
        "name": 'Basic Code flow with ID Token',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an ID Token.'),
        "depends": ["basic-code-authn"],
        "sequence": ["login-form-approve", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    'basic-code-idtoken-userdata': {
        "name": 'Basic Code flow with ID Token and User data',
        "descr": ('Very basic test of a Provider using the authorization code'
                  ' flow, but in addition to retrieve an ID Token,',
                  ' this test flow also tried to obtain user data.'),
        "depends": ['basic-code-idtoken'],
        "sequence": ["login-form-approve", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"]
    },
    'basic-code-idtoken-check_id': {
        "name": 'Basic Code flow with ID Token and Check ID',
        "descr": ('Very basic test of a Provider using the authorization code'
                  ' flow, but in addition to retrieve an ID Token,',
                  ' this test flow also tried to verify the ID Token.'),
        "depends": ['basic-code-idtoken'],
        "sequence": ["login-form-approve", "access-token-request",
                     "check-id-request"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"]
    },
}