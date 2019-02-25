keys = [
    {"type": "RSA", "key": "cp_keys/key.pem", "use": ["enc", "sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]

ISSUER = 'http://localhost'
SERVICE_URL = "{issuer}/verify"

USER_PASSWORD_END_POINTS = ["user_password", "multi_user_password_saml_verify",
                            "multi_user_password_js_verify"]
SAML_END_POINTS = ['saml', "multi_saml_pass"]
JAVASCRIPT_END_POINTS = ['javascript_login', "multi_javascript_login"]

AUTHENTICATION = {
    "SAML": {"ACR": "SAML", "WEIGHT": 1, "END_POINTS": SAML_END_POINTS},
    "UserPassword": {"ACR": "PASSWORD", "WEIGHT": 2,
                     "END_POINTS": USER_PASSWORD_END_POINTS},
    "SamlPass": {"ACR": "SAML_PASS", "WEIGHT": 3},
    "JavascriptLogin": {"ACR": "JAVASCRIPT_LOGIN", "WEIGHT": 4,
                        "END_POINTS": JAVASCRIPT_END_POINTS},
    "JavascriptPass": {"ACR": "JAVASCRIPT_PASS", "WEIGHT": 5},
}

COOKIENAME= 'pyoic'
COOKIETTL = 4*60  # 4 hours
SYM_KEY = "SoLittleTime,Got"

SERVER_CERT = "certs/server.crt"
SERVER_KEY = "certs/server.key"
# CERT_CHAIN="certs/chain.pem"
CERT_CHAIN = None

# =======  SAML ==============
# User information is collected with SAML
# USERINFO = "SAML"
# User information is collected with a SAML attribute authority
# USERINFO = "AA"
# Name of the Service Provider configuration file.
SP_CONFIG="sp_conf"
# Dictionary with user information for the SAML users. Must be empty.
SAML = {}

# =======  SIMPLE DATABASE ==============

USERINFO = "SIMPLE"

USERDB = {
    "diana": {
        "sub": "dikr0001",
        "name": "Diana Krall",
        "given_name": "Diana",
        "family_name": "Krall",
        "nickname": "Dina",
        "email": "diana@example.org",
        "email_verified": False,
        "phone_number": "+46 90 7865000",
        "address": {
            "street_address": "Umeå Universitet",
            "locality": "Umeå",
            "postal_code": "SE-90187",
            "country": "Sweden"
        },
    },
    "babs": {
        "sub": "babs0001",
        "name": "Barbara J Jensen",
        "given_name": "Barbara",
        "family_name": "Jensen",
        "nickname": "babs",
        "email": "babs@example.com",
        "email_verified": True,
        "address": {
            "street_address": "100 Universal City Plaza",
            "locality": "Hollywood",
            "region": "CA",
            "postal_code": "91608",
            "country": "USA",
        },
    },
    "upper": {
        "sub": "uppe0001",
        "name": "Upper Crust",
        "given_name": "Upper",
        "family_name": "Crust",
        "email": "uc@example.com",
        "email_verified": True,
    }
}

