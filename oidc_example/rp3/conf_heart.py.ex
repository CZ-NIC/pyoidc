BASE = "https://localhost"
#BASE = "https://130.239.200.165"

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
    "redirect_uris": ["{base}authz_cb/{iss}"],
    "post_logout_redirect_uris": ["{base}logout_success/{iss}"],
    "response_types": ["code"],
    # 'token_endpoint_auth_method': ''
}

BEHAVIOUR = {
    "response_type": "code",
    "scope": ["offline_access"],
}

ACR_VALUES = []

# The keys in then CLIENTS dictionary are the OPs short user friendly name
# not the issuer (iss) name.

CLIENTS = {
    # The ones that support web finger, OP discovery and dynamic client
    # registration.
    # This is the default, any client that is not specifically listed here is
    # expected to support dynamic discovery and registration.
    "": {
        "client_info": ME,
        "behaviour": BEHAVIOUR,
        'config': {
            'code_challenge': {
                'length': 64,
                'method': 'S256'
            }
        }
    },
}

USERINFO = False
RESOURCE_SERVER = None
CLIENT_TYPE = 'OAuth2'

KEY_SPECIFICATION = [
    {"type": "RSA", "use": ["enc", "sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc", "sig"]},
]
