from oic.utils.keystore import rsa_load
from oic.oauth2 import rndstr
from oic.oic.consumer import Consumer
from oic.utils.sdb import SessionDB
from fakeoicsrv import MyFakeOICServer

__author__ = 'rohe0002'

CLIENT_SECRET = "abcdefghijklmnop"
CLIENT_ID = "client_1"

rsapub = rsa_load("../oc3/certs/mycert.key")

SRVKEYS = [
    ["abcdefghijklmnop", "hmac", "ver", "client_1"],
    ["abcdefghijklmnop", "hmac", "sig", "client_1"],
    [rsapub, "rsa", "sig", "."],
    [rsapub, "rsa", "ver", "."]
]

CLIKEYS = [
    ["abcdefghijklmnop", "hmac", "ver", "."],
    ["abcdefghijklmnop", "hmac", "sig", "."],
    [rsapub, "rsa", "sig", "http://localhost:8088"],
    [rsapub, "rsa", "ver", "http://localhost:8088"]
]

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

SERVER_INFO ={
    "version":"3.0",
    "issuer":"https://localhost:8088",
    "authorization_endpoint":"http://localhost:8088/authorization",
    "token_endpoint":"http://localhost:8088/token",
    "userinfo_endpoint":"http://localhost:8088/userinfo",
    "flows_supported":["code","token"],
    }

CONFIG = {
    "authz_page": "authz",
    "scope": ["openid"],
    "response_type": "code",
    "request_method": "parameter",
    #"temp_dir": "./tmp",
    #"flow_type":
    "password":"hemligt",
    "max_age": 3600,
    #client_secret
    "user_info":{
        "claims": {
            "name":None,
            },
        "format": "signed"
    }
}

CLIENT_CONFIG = {"client_id": CLIENT_ID, "jwt_keys": CLIKEYS}

def start_response(status=200, headers=None):
    if headers is None:
        return "status=%s, headers={}" % (status, )
    else:
        return "status=%s, headers=%s" % (status, headers)

def _eq(l1, l2):
    return set(l1) == set(l2)

consumer = Consumer(SessionDB(), CONFIG, CLIENT_CONFIG, SERVER_INFO)
mfos = MyFakeOICServer(SRVKEYS, "http://localhost:8088")
consumer.http_request = mfos.http_request
consumer.redirect_uris = ["http://example.com/authz"]
consumer.state = "state0"
consumer.nonce = rndstr()
consumer.client_secret = "hemlig"
consumer.secret_type = "basic"
consumer.config["response_type"] = ["id_token", "token"]

args = {
    "client_id": consumer.client_id,
    "response_type": consumer.config["response_type"],
    "scope": ["openid"],
    }

result = consumer.do_authorization_request(state=consumer.state,
                                           request_args=args)
