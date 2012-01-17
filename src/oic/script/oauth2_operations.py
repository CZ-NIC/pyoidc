from oic.script.opfunc import *
#from opfunc import *

RESPOND = {
    "method": "POST",
    }

AUTHZREQ_CODE = {
    "request": "AuthorizationRequest",
    "method": "GET",
    "args": {
        "request": {"response_type": "code"},
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

ACCESS_TOKEN_REQUEST_CLI_SECRET_POST = {
    "request":"AccessTokenRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "client_secret_post"}
    },
    }

ACCESS_TOKEN_REQUEST_CLI_SECRET_GET = {
    "request":"AccessTokenRequest",
    "method": "GET",
    "args": {
        "kw": {"authn_method": "client_secret_post"}
    },
    }

ACCESS_TOKEN_REQUEST_FACEBOOK = {
    "request":("facebook","AccessTokenRequest"),
    "method": "GET",
    "args": {
        "kw": {"authn_method": "client_secret_post"}
    },
    }

ACCESS_TOKEN_RESPONSE_FACEBOOK = {
    "response": ("facebook", "AccessTokenResponse"),
    "where": "body",
    "type": "urlencoded"
}

PHASES= {
    "login": ([AUTHZREQ_CODE], AUTHZRESP),
    "login-form": ([AUTHZREQ_CODE, LOGIN_FORM], AUTHZRESP),
    "login-form-approve": ([AUTHZREQ_CODE, LOGIN_FORM, APPROVE_FORM],
                           AUTHZRESP),
    "access-token-request-post":([ACCESS_TOKEN_REQUEST_CLI_SECRET_POST],
                                 ACCESS_TOKEN_RESPONSE),
    "access-token-request-get":([ACCESS_TOKEN_REQUEST_CLI_SECRET_GET],
                                ACCESS_TOKEN_RESPONSE),
    "facebook-access-token-request-get":([ACCESS_TOKEN_REQUEST_FACEBOOK],
                                         ACCESS_TOKEN_RESPONSE_FACEBOOK),
    "coip-login": ([AUTHZREQ_CODE, CHOSE, SELECT_FORM, LOGIN_FORM, POST_FORM],
                   AUTHZRESP),
}


FLOWS = {
    'basic-code-authn': {
        "name": 'Basic Code flow with authentication',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an ID Token.'),
        "sequence": ["login-form"],
        "endpoints": ["authorization_endpoint"]
    },
    'basic-code-idtoken-post': {
        "name": 'Basic Code flow with ID Token',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an ID Token.'),
        "depends": ["basic-code-authn"],
        "sequence": ["login-form", "access-token-request-post"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    'basic-code-idtoken-get': {
        "name": 'Basic Code flow with ID Token',
        "descr": ('Very basic test of a Provider using the authorization code ',
                  'flow. The test tool acting as a consumer is very relaxed',
                  'and tries to obtain an ID Token.'),
        "depends": ["basic-code-authn"],
        "sequence": ["login-form", "access-token-request-get"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    'facebook-idtoken-get': {
        "name": 'Facebook flow with ID Token',
        "descr": ('Facebook specific flow'),
        "depends": ["basic-code-authn"],
        "sequence": ["login-form", "facebook-access-token-request-get"],
        "endpoints": ["authorization_endpoint", "token_endpoint"]
    },
    'coip-authn': {
        "sequence": ["coip-login"],
        "endpoints": ["authorization_endpoint"]
    },

}