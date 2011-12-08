__author__ = 'rohe0002'

from oic.oic import Server

from oic.oic.consumer import Consumer
from oic.oic.consumer import IGNORE
from oic.utils.sdb import SessionDB

JWT_KEY = "abcdefghijklmop"
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
#    "user_info_endpoint":"http://localhost:8088/user_info",
    "flows_supported":["code","token"],
}

def start_response(status=200, headers=None):
    if headers is None:
        return "status=%s, headers={}" % (status, )
    else:
        return "status=%s, headers=%s" % (status, headers)

def _eq(l1, l2):
    return set(l1) == set(l2)

class DEVNULL():
    #noinspection PyUnusedLocal
    def info(self, txt):
        return

class TestOICConsumer():

    def setup_class(self):
        config = {
            "authz_page": "authz",
            "scope": ["openid"],
            "response_type": "code",
            "key": JWT_KEY,
            "request_method": "parameter",
            #"temp_dir": "./tmp",
            #"flow_type":
            "password":"hemligt",
            #client_secret
        }
        client_config = {
            "client_id": "client0"
        }

        self.consumer = Consumer(SessionDB(), config, client_config,
                                 SERVER_INFO)

    def test_init(self):
        assert self.consumer

    def test_backup_keys(self):
        keys = self.consumer.__dict__.keys()
        print keys
        _dict = self.consumer.dictionary()
        print _dict.keys()
        dkeys = [key for key in keys if key not in _dict.keys()]
        print dkeys
        assert _eq(dkeys, IGNORE)

    def test_backup_restore(self):

        _dict = self.consumer.__dict__.items()

        self.consumer._backup("sid")
        self.consumer.restore("sid")

        assert _dict == self.consumer.__dict__.items()

        self.consumer.authorization_endpoint = "http://example.com/authorization"

        assert _dict != self.consumer.__dict__.items()

        self.consumer.restore("sid")

        assert _dict == self.consumer.__dict__.items()

    def test_backup_restore_update(self):

        self.consumer.authorization_endpoint = "http://example.com/authorization"
        self.consumer.token_endpoint = "http://example.com/token"
        self.consumer.user_info_endpoint = "http://example.com/userinfo"

        self.consumer._backup("sid")

        self.consumer.authorization_endpoint = "http://example.org/authorization"
        self.consumer.token_endpoint = "http://example.org/token"
        self.consumer.user_info_endpoint = ""

        assert self.consumer.authorization_endpoint == "http://example.org/authorization"
        assert self.consumer.token_endpoint == "http://example.org/token"
        assert self.consumer.user_info_endpoint == ""

        self.consumer.update("sid")

        assert self.consumer.authorization_endpoint == "http://example.org/authorization"
        assert self.consumer.token_endpoint == "http://example.org/token"
        assert self.consumer.user_info_endpoint == "http://example.com/userinfo"

    def test_begin(self):
        self.consumer.authorization_endpoint = "http://example.com/authorization"
        srv = Server()
        location = self.consumer.begin(BASE_ENVIRON, start_response, DEVNULL())
        print location
        authreq = srv.parse_authorization_request(url=location)
        print authreq.keys()
        assert _eq(authreq.keys(), ['nonce', 'request', 'state',
                                    'redirect_uri', 'response_type',
                                    'client_id', 'scope'])
        
        assert authreq.state == self.consumer.state
        assert authreq.scope == self.consumer.config["scope"]
        assert authreq.client_id == self.consumer.client_id
        assert authreq.nonce == self.consumer.nonce
