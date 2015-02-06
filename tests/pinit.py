import os

from mako.lookup import TemplateLookup
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authn.client import verify_client
from oic.utils.authz import AuthzHandling
from oic.utils.userinfo import UserInfo

__author__ = 'rohe0002'

from oic.utils.sdb import SessionDB
from oic.oic.provider import Provider
from oic.utils.keyio import KeyBundle, keybundle_from_local_file
from oic.utils.keyio import KeyJar


BASE_PATH = os.path.dirname(os.path.abspath(__file__))

CLIENT_CONFIG = {
    "client_id": "number5",
    "ca_certs": "/usr/local/etc/oic/ca_certs.txt",
    "client_timeout": 0
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "scope": ["openid"],
    "response_type": ["code"],
    "user_info": {
        "claims": {
            "name": None,
            "email": None,
            "nickname": None
        }
    },
    "request_method": "param"
}

SERVER_INFO = {
    "version": "3.0",
    "issuer": "https://connect-op.heroku.com",
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    "flows_supported": ["code", "token", "code token"],
}

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KC_SYM = KeyBundle([{"kty": "oct", "key": CLIENT_SECRET, "use": "ver"},
                     {"kty": "oct", "key": CLIENT_SECRET, "use": "sig"}])
KC_SYM2 = KeyBundle([{"kty": "oct", "key": "drickyoughurt", "use": "sig"},
                      {"kty": "oct", "key": "drickyoughurt", "use": "ver"}])

KC_RSA = keybundle_from_local_file("%s/rsa.key" % BASE_PATH,
                                   "rsa", ["ver", "sig"])

KEYJAR = KeyJar()
KEYJAR[CLIENT_ID] = [KC_SYM, KC_RSA]
KEYJAR["number5"] = [KC_SYM2, KC_RSA]
KEYJAR[""] = KC_RSA

CDB = {
    "number5": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        #"jwk_key": CONSUMER_CONFIG["key"],
        "redirect_uris": [("http://localhost:8087/authz", None)],
        },
    "a1b2c3": {
        "redirect_uris": [("http://localhost:8087/authz", None)]
    },
    "client0": {
        "redirect_uris": [("http://www.example.org/authz", None)]
    },
    CLIENT_ID: {
        "client_secret": CLIENT_SECRET,
        }

}

USERDB = {
    "user": {
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
        "sub": "user"
    }
}

URLMAP = {CLIENT_ID: ["https://example.com/authz"]}

PASSWD = {"user": "password"}

ROOT = '../oc3/'
tl = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                    module_directory=ROOT + 'modules',
                    input_encoding='utf-8', output_encoding='utf-8')

AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("1", UsernamePasswordMako(None, "login.mako", tl, PASSWD,
                                           "authenticated"))

# dealing with authorization
AUTHZ = AuthzHandling()
SYMKEY = "symmetric key used to encrypt cookie info"
USERINFO = UserInfo(USERDB)

provider_init = Provider("pyoicserv", SessionDB(SERVER_INFO["issuer"]), CDB,
                         AUTHN_BROKER, USERINFO,
                         AUTHZ, verify_client, SYMKEY, urlmap=URLMAP,
                         keyjar=KEYJAR)
