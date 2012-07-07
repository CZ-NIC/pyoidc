
__author__ = 'rohe0002'

import sys
import StringIO
import urllib

from oic.oic.message import OpenIDSchema
from src.oic.utils.sdb import SessionDB

from src.oic.oic.provider import Provider

from src.oic.oauth2.provider import AuthnFailure
from src.oic.utils import http_util

CLIENT_CONFIG = {
    "client_id": "number5",
    "ca_certs": "/usr/local/etc/oic/ca_certs.txt",
    "disable_ssl_certificate_validation":False,
    "expire_in":600,
    "client_timeout":0
}

CONSUMER_CONFIG = {
    #"debug": 1,
    "authz_page": "/authz",
    #"password": args.passwd,
    "scope": ["openid"],
    "response_type": ["code"],
    #"expire_in": 600,
    "user_info": {
        "claims": {
            "name": None,
            "email": None,
            "nickname": None
        }
    }
}

SERVER_INFO ={
    "version":"3.0",
    "issuer":"https://connect-op.heroku.com",
    "authorization_endpoint":"http://localhost:8088/authorization",
    "token_endpoint":"http://localhost:8088/token",
    #"userinfo_endpoint":"http://localhost:8088/user_info",
    #"check_id_endpoint":"http://localhost:8088/id_token",
    #"registration_endpoint":"https://connect-op.heroku.com/connect/client",
    #"scopes_supported":["openid","profile","email","address","PPID"],
    "flows_supported":["code","token","code token"],
    #"identifiers_supported":["public","ppid"],
    #"x509_url":"https://connect-op.heroku.com/cert.pem"
}

BASE_ENVIRON = {'SERVER_PROTOCOL': 'HTTP/1.1',
                'REQUEST_METHOD': 'GET',
                'QUERY_STRING': '',
                'HTTP_CONNECTION': 'keep-alive',
                'REMOTE_ADDR': '127.0.0.1',
                'wsgi.url_scheme': 'http',
                'SERVER_PORT': '8087',
                'PATH_INFO': '/register',
                'HTTP_HOST': 'localhost:8087',
                'HTTP_ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'HTTP_ACCEPT_LANGUAGE': 'sv-se',
                'CONTENT_TYPE': 'text/plain',
                'REMOTE_HOST': '1.0.0.127.in-addr.arpa',
                'HTTP_ACCEPT_ENCODING': 'gzip, deflate',
                'COMMAND_MODE': 'unix2003'}

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

KEYS = [
    [CLIENT_SECRET, "hmac", "ver", CLIENT_ID],
    [CLIENT_SECRET, "hmac", "sig", CLIENT_ID],
    ["drickyoughurt", "hmac", "ver", "number5"],
    ["drickyoughurt", "hmac", "sig", "number5"],
]

#SIGN_KEY = {"hmac": ["abcdefghijklmnop"]}

CDB = {
    "number5": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        #"jwk_key": CONSUMER_CONFIG["key"],
        "redirect_uris": ["http://localhost:8087/authz"]
    },
    "a1b2c3":{
        "redirect_uris": ["http://localhost:8087/authz"]
    },
    "client0":{
        "redirect_uris": ["http://www.example.org/authz"]
    },
    CLIENT_ID: {
        "client_secret": CLIENT_SECRET,
        }

}

#noinspection PyUnusedLocal
def start_response(status, headers=None):
    return

def do_authentication(environ, start_response, bsid):
    resp = http_util.Response("<form>%s</form>" % bsid)
    return resp(environ, start_response)

#noinspection PyUnusedLocal
def do_authorization(user, session=None):
    if user == "user":
        return "ALL"
    else:
        raise Exception("No Authorization defined")

def verify_username_and_password(dic):
    try:
        user = dic["login"][0]
    except KeyError:
        raise AuthnFailure("Authentication failed")

    if user == "user":
        return True, user
    elif user == "hannibal":
        raise AuthnFailure("Not allowed to use this service (%s)" % user)
    else:
        if user:
            return False, user
        else:
            raise AuthnFailure("Missing user name")


#noinspection PyUnusedLocal
def verify_client(environ, areq, cdb):
    identity = areq.client_id
    secret = areq.client_secret
    if identity:
        if identity == CLIENT_ID and secret == CLIENT_SECRET:
            return True
        else:
            return False

    return False

def create_return_form_env(user, password, sid):
    _dict = {
        "login": user,
        "password": password,
        "sid": sid
    }

    environ = BASE_ENVIRON.copy()
    environ["REQUEST_METHOD"] = "POST"

    str = urllib.urlencode(_dict)
    environ["CONTENT_LENGTH"] = len(str)

    fil = StringIO.StringIO(buf=str)
    environ["wsgi.input"] = fil

    return environ

#noinspection PyUnusedLocal
def user_info(oicsrv, userdb, user_id, client_id, user_info):
    identity = userdb[user_id]
    result = {}
    for key, restr in user_info.claims.items():
        try:
            result[key] = identity[key]
        except KeyError:
            if restr == {"optional": True}:
                pass
            else:
                raise Exception("Missing property '%s'" % key)

    return OpenIDSchema(**result)

class LOG():
    def info(self, txt):
        print >> sys.stdout, "INFO: %s" % txt

    def error(self, txt):
        print >> sys.stdout, "ERROR: %s" % txt

    def debug(self, txt):
        print >> sys.stdout, "DEBUG: %s" % txt

FUNCTIONS = {
    "authenticate": do_authentication,
    "authorize": do_authorization,
    "verify_user": verify_username_and_password,
    "verify_client": verify_client,
    "userinfo": user_info,
    }

USERDB = {
    "user":{
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
        "user_id": "user"
    }
}

URLMAP = {"client1": ["https://example.com/authz"]}

provider_init = Provider("pyoicserv", SessionDB(), CDB, FUNCTIONS,
                         userdb=USERDB, urlmap=URLMAP, jwt_keys=KEYS)

# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------

server = provider_init
environ0 = create_return_form_env("haden", "secret", "sid1")
resp1 = server.authenticated(environ0, start_response)
print resp1
assert resp1 == ['<html>Wrong password</html>']

environ1 = create_return_form_env("", "secret", "sid2")
resp2 = server.authenticated(environ1, start_response)
print resp2