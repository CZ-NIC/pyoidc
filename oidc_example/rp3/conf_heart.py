# BASE = "https://lingon.ladok.umu.se"
BASE = "https://localhost"

# If BASE is https these has to be specified
SERVER_CERT = "certs/server.crt"
SERVER_KEY = "certs/server.key"
CA_BUNDLE = None
CERT_CHAIN = None

VERIFY_SSL = False

# information used when registering the client, this may be the same for all OPs

ME = {
    "application_type": "web",
    "application_name": "idpproxy",
    "contacts": ["ops@example.com"],
    "redirect_uris": ["{base}authz_cb"],
    "post_logout_redirect_uris": ["{base}logout_success"],
    "response_types": ["code"],
    'token_endpoint_auth_method': ['private_key_jwt']
}

BEHAVIOUR = {
    "response_type": "code",
    "scope": ["openid", "profile", "email", "address", "phone"],
}

ACR_VALUES = ["PASSWD"]

# The keys in this dictionary are the OPs short userfriendly name
# not the issuer (iss) name.

CLIENTS = {
    # The ones that support webfinger, OP discovery and client registration
    # This is the default, any client that is not listed here is expected to
    # support dynamic discovery and registration.
    "": {
        "client_info": ME,
        "behaviour": BEHAVIOUR
    },
}

KEY_SPECIFICATION = [
    {"type": "RSA", "key": "keys/pyoidc_enc", "use": ["enc"]},
    {"type": "RSA", "key": "keys/pyoidc_sig", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]

CLIENT_TYPE = 'OAUTH2'  # one of OIDC/OAUTH2
USERINFO = False
