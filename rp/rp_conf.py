import pyoidc
from rp.pyoidc import pyoidcOAuth2, pyoidcOIC
PORT=8666
BASE="http://hashog.umdc.umu.se:"+str(PORT) + "/"
SERVICE = {
    "pyoidcOICDyn":{
        "opKey" : "pyoidcOICDyn",
        "client_id" : "None",
        "client_secret" : "None",
        "description": "Use discovery to login at pyoidc oc3 server with OpenId connect.",
        "class": pyoidcOIC,
        "srv_discovery_url": "https://localhost:8092/",
        "scope": ["openid", "profile"],
        "name": "pyoidcOIC",
    },
    "pyoidcOICStatic":{#{'client_secret': '1e1254a35bf2000dff6daaef35660a85f7f17b5a0d5192da7838dfb1', 'policy_url': '', 'redirect_uris': [('http://hashog.umdc.umu.se:8666/pyoidcOICStatic', None)], 'logo_url': '', 'client_id': 'VJNL62bPdOnn'}
        "opKey" : "pyoidcOICStatic",
        "client_id" : "VJNL62bPdOnn",
        "client_secret" : "1e1254a35bf2000dff6daaef35660a85f7f17b5a0d5192da7838dfb1",
        "description": "User static settings to login at pyoidc oc3 server with OpenId connect.",
        "class": pyoidcOIC,
        "authorization_endpoint": 'https://localhost:8092/authorization',
        "token_endpoint": "https://localhost:8092/token",
        "userinfo_endpoint": "https://localhost:8092/userinfo",
        "keys" : ["https://localhost:8092/","https://localhost:8092/static/jwks.json"],
        "scope": ["openid", "profile"],
        "name": "pyoidcOIC",
    },
    "pyoidcOAuth":{ #{'client_secret': '1156c63d5cc94f62ca0fb717ab29755b7f7664bf3c5a84c04aede560', 'policy_url': '', 'redirect_uris': [('http://hashog.umdc.umu.se:8666/pyoidcOAuth', None)], 'logo_url': '', 'client_id': 'u1fD2wvxhw0S'}
        "opKey" : "pyoidcOAuth",
        "client_id" : "u1fD2wvxhw0S",
        "client_secret" : "1156c63d5cc94f62ca0fb717ab29755b7f7664bf3c5a84c04aede560",
        "description": "Login at pyoidc oc3 server with OAuth 2.0.",
        "class": pyoidcOAuth2,
        "authorization_endpoint": 'https://localhost:8092/authorization',
        "token_endpoint": "https://localhost:8092/token",
        "userinfo_endpoint": "https://localhost:8092/userinfo",
        "scope": ["openid", "profile"],
        "name": "pyoidcOAuth",
    }

}
