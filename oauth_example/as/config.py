from mako.lookup import TemplateLookup

HOST = "localhost"
# HOST = "lingon.ladok.umu.se"
# HOST = "lingon.catalogix.se"

baseurl = "https://%s" % HOST
issuer = "%s:%%d" % baseurl

# Where to go for verifying the authentication info
SERVICE_URL = "%s/verify" % issuer
# Where to return the user after the authentication has been completed
RETURN_TO = "%s/authorization" % issuer

# This is used to pick a subset of users from the set of users that can
# authenticate at this server
VALIDATOR = {
    "type": "ldap",
    "conf": {
        "uri": "ldaps://ldap.umu.se",
        "base": "dc=umu, dc=se",
        "filter_pattern": "(uid=%s)",
        "user": "",
        "passwd": "",
        "attr": ["eduPersonScopedAffiliation", "eduPersonAffiliation"],
    },
    "args": {
        "verifyAttr": "eduPersonAffiliation",
        "verifyAttrValid": ['employee', 'staff', 'student']
    }
}

# ============================================================================
# Static password database
# The password interface is supposed to act as a dictionary. Which it in this
# case is.
# ============================================================================

PASSWD = {"diana": "krall",
          "babs": "howes",
          "upper": "crust",
          "rohe0002": "StevieRay",
          "haho0032": "qwerty"}

ROOT = './'

# ACR = Authentication Class Reference
# WEIGHT = your view on the strength of the method, higher value = better
# SERVICE_URL = After the authentication, this is where the user should be
#   redirected to.

AUTHN_METHOD = {
    "UserPassword": {
        "ACR": "PASSWORD",
        "WEIGHT": 1,
        "URL": SERVICE_URL,
        "config": {
            "lookup": TemplateLookup(directories=[ROOT + 'templates',
                                                  ROOT + 'htdocs'],
                                     module_directory=ROOT + 'modules',
                                     input_encoding='utf-8',
                                     output_encoding='utf-8'),
            "passwd": PASSWD,
            "return_to": RETURN_TO
        }
    },
}

AUTHN = "Simple"

COOKIENAME = 'pyoic'
COOKIETTL = 4 * 60  # 4 hours
SYM_KEY = "IfIwerelookingfo"  # 16 bytes for AES_128 which is the default
SERVER_CERT = "%s/certs/server.crt" % ROOT
SERVER_KEY = "%s/certs/server.key" % ROOT
# CERT_CHAIN="certs/chain.pem"
CERT_CHAIN = None

keys = [
    {"type": "RSA", "key": "keys/key.pem", "use": ["enc", "sig"]},
    {"type": "EC", "crv": "P-256", "use": ["sig"]},
    {"type": "EC", "crv": "P-256", "use": ["enc"]}
]

CAPABILITIES = {
    "token_endpoint_auth_methods_supported": ["private_key_jwt"],
    "grant_types_supported": ["authorization_code", "implicit",
                              'client_credentials'],
    "scopes_supported": ["offline_access"],
    'response_types_supported': ['code', 'token']
}

BEHAVIOR = {
    'client_registration':{
        'map': {
            'grant_type2response_type': {
                'authorization_code': 'code',
                'implicit': 'token'
            }
        },
        'single': ['response_types'],
        'allow': {
            'grant_types': [
                'authorization_code',
                'implicit',
                #  'client_credentials'  Not allowed
            ]
        }
    }
}

TRUSTED_REGISTRATION_ENTITIES = [{
    'iss': 'https://has.example.com/tre',
    'jwks': 'tre.jwks',
}]
