import StringIO
import sys

from oic.oic.message import OpenIDSchema
from oic.utils.keyio import KeyChain

from oic.oic.claims_provider import ClaimsClient
from oic.oic.claims_provider import ClaimsServer

#noinspection PyUnusedLocal
def user_info(oicsrv, userdb, user_id, client_id="", user_info_claims=None):
    #print >> sys.stderr, "claims: %s" % user_info_claims
    identity = userdb[user_id]
    if user_info_claims:
        result = {}
        for key, restr in user_info_claims.items():
            try:
                result[key] = identity[key]
            except KeyError:
                if restr == {"essential": True}:
                    raise Exception("Missing property '%s'" % key)
    else:
        result = identity

    return OpenIDSchema(**result)

class LOG():
    def info(self, txt):
        print >> sys.stdout, "INFO: %s" % txt

    def error(self, txt):
        print >> sys.stdout, "ERROR: %s" % txt

    def debug(self, txt):
        print >> sys.stdout, "DEBUG: %s" % txt

#noinspection PyUnusedLocal
def start_response(status, headers=None):
    return

USERDB = {
    "diana":{
        "birthdate": "02/14/2012",
        "gender": "female"
    }
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

CDB = {
    "client_1": { "client_secret": "hemlig"}
}

def verify_client(env, req, cdb):
    return True

FUNCTIONS = {
    "verify_client": verify_client,
    "userinfo": user_info
}

cc = ClaimsClient(client_id="client_1")
cc.client_secret="hemlig"

req = cc.construct_UserClaimsRequest(request_args={"user_id": "diana",
                                                   "claims_names":["gender", "birthdate"]})

srv = ClaimsServer("name", None, CDB, FUNCTIONS, USERDB)

srv.keyjar[""] = [KeyChain(source="file://rsa.key", usage=["ver", "sig"])]
assert srv

environ = BASE_ENVIRON.copy()
environ["REQUEST_METHOD"] = "POST"
txt = req.to_urlencoded()
environ["CONTENT_LENGTH"] = len(txt)
fil = StringIO.StringIO(buf=txt)
environ["wsgi.input"] = fil

resp = srv.claims_endpoint(environ, start_response, LOG())

print resp
