from mako.lookup import TemplateLookup
from mako.runtime import UNDEFINED
from oic.oauth2 import rndstr
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import AuthzHandling, Implicit
from oic.utils.http_util import Response

from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import AccessTokenRequest
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import TokenErrorResponse

from oic.utils import sdb
from oic.oauth2.consumer import Consumer
from oic.oauth2.provider import Provider

CLIENT_CONFIG = {
    "client_id": "client1",
    "ca_certs": "/usr/local/etc/oic/ca_certs.txt",
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "flow_type": "code",
    #"password": args.passwd,
    "scope": [],
    "response_type": "code",
    #"expire_in": 600,
}

SERVER_INFO = {
    "version": "3.0",
    "issuer": "https://connect-op.heroku.com",
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    #"userinfo_endpoint":"http://localhost:8088/user_info",
    #"check_id_endpoint":"http://localhost:8088/id_token",
    #"registration_endpoint":"https://connect-op.heroku.com/connect/client",
    #"scopes_supported":["openid","profile","email","address","PPID"],
    "flows_supported": ["code", "token", "code token"],
    #"identifiers_supported":["public","ppid"],
    #"x509_url":"https://connect-op.heroku.com/cert.pem"
}

CDB = {
    "a1b2c3": {
        "password": "hemligt",
        "client_secret": "drickyoughurt"
    },
    "client1": {
        "client_secret": "hemlighet",
        "redirect_uris": [("http://localhost:8087/authz", None)]
    }
}

PASSWD = {"user": "password"}

ROOT = '../oc3/'
tl = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                    module_directory=ROOT + 'modules',
                    input_encoding='utf-8', output_encoding='utf-8')


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        return {"uid": self.user}

AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))

# dealing with authorization
AUTHZ = Implicit()


def content_type(headers):
    for key, val in headers:
        if key == "Content-type":
            if val == "application/json":
                return "json"


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_provider_init():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, AUTHN_BROKER, AUTHZ,
                        verify_client)

    assert provider

    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, AUTHN_BROKER, AUTHZ,
                        verify_client,
                        urlmap={"client1": ["https://example.com/authz"]})

    assert provider.urlmap["client1"] == ["https://example.com/authz"]


def test_provider_authorization_endpoint():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, AUTHN_BROKER, AUTHZ,
                        verify_client)

    bib = {"scope": ["openid"],
           "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
           "redirect_uri": "http://localhost:8087authz",
           "response_type": ["code"],
           "client_id": "a1b2c3"}

    arq = AuthorizationRequest(**bib)

    QUERY_STRING = arq.to_urlencoded()

    resp = provider.authorization_endpoint(request=QUERY_STRING)

    assert isinstance(resp, Response)


def test_provider_authenticated():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, AUTHN_BROKER, AUTHZ,
                        verify_client, symkey=rndstr(16))
    _session_db = {}
    cons = Consumer(_session_db, client_config=CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True

    location = cons.begin("http://localhost:8087",
                          "http://localhost:8088/authorization")

    query_string = location.split("?")[1]

    resp = provider.authorization_endpoint(query_string)
    assert resp.status == "302 Found"
    print resp.headers
    print resp.message
    if content_type(resp.headers) == "json":
        resp = resp.message
    else:
        resp = resp.message.split("?")[1]
    aresp = cons.handle_authorization_response(query=resp)

    print aresp.keys()
    assert aresp.type() == "AuthorizationResponse"
    assert _eq(aresp.keys(), ['state', 'code'])

    print cons.grant[cons.state].keys()
    assert _eq(cons.grant[cons.state].keys(), ['tokens', 'code', 'exp_in',
                                               'seed', 'id_token',
                                               'grant_expiration_time'])


def test_provider_authenticated_token():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, AUTHN_BROKER, AUTHZ,
                        verify_client, symkey=rndstr(16))
    _session_db = {}
    cons = Consumer(_session_db, client_config=CLIENT_CONFIG,
                    server_info=SERVER_INFO, **CONSUMER_CONFIG)
    cons.debug = True

    location = cons.begin("http://localhost:8087",
                          "http://localhost:8088/authorization",
                          "token")

    QUERY_STRING = location.split("?")[1]
    resp = provider.authorization_endpoint(QUERY_STRING)
    print resp.headers
    print resp.message
    txt = resp.message
    assert "access_token=" in txt
    assert "token_type=Bearer" in txt


# def test_provider_authenticated_none():
#     provider = Provider("pyoicserv", sdb.SessionDB(), CDB, AUTHN_BROKER, AUTHZ,
#                         verify_client)
#     _session_db = {}
#     cons = Consumer(_session_db, client_config=CLIENT_CONFIG,
#                     server_info=SERVER_INFO, **CONSUMER_CONFIG)
#     cons.debug = True
#
#     location = cons.begin("http://localhost:8087",
#                           "http://localhost:8088/authorization",
#                           "none")
#
#     QUERY_STRING = location.split("?")[1]
#
#     resp2 = provider.authorization_endpoint(request=QUERY_STRING)
#
#     location = resp2.message
#     print location
#
#     assert location.startswith("http://localhost:8087/authz")
#     query = location.split("?")[1]
#     assert query.startswith("state=")
#     assert "&" not in query


def test_token_endpoint():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, AUTHN_BROKER, AUTHZ,
                        verify_client, symkey=rndstr(16))

    authreq = AuthorizationRequest(state="state",
                                   redirect_uri="http://example.com/authz",
                                   client_id="client1")

    _sdb = provider.sdb
    sid = _sdb.token.key(user="user_id", areq=authreq)
    access_grant = _sdb.token(sid=sid)
    _sdb[sid] = {
        "oauth_state": "authz",
        "user_id": "user_id",
        "authzreq": "",
        "client_id": "client1",
        "code": access_grant,
        "code_used": False,
        "redirect_uri": "http://example.com/authz"
    }

    # Construct Access token request
    areq = AccessTokenRequest(code=access_grant,
                              redirect_uri="http://example.com/authz",
                              client_id="client1", client_secret="hemlighet",)

    print areq.to_dict()
    resp = provider.token_endpoint(request=areq.to_urlencoded())
    print resp.message
    atr = AccessTokenResponse().deserialize(resp.message, "json")

    print atr.keys()
    assert _eq(atr.keys(), ['access_token', 'expires_in', 'token_type',
                            'refresh_token'])


def test_token_endpoint_unauth():
    provider = Provider("pyoicserv", sdb.SessionDB(), CDB, AUTHN_BROKER, AUTHZ,
                        verify_client, symkey=rndstr(16))

    authreq = AuthorizationRequest(state="state",
                                   redirect_uri="http://example.com/authz",
                                   client_id="client1")

    _sdb = provider.sdb
    sid = _sdb.token.key(user="user_id", areq=authreq)
    access_grant = _sdb.token(sid=sid)
    _sdb[sid] = {
        "oauth_state": "authz",
        "user_id": "user_id",
        "authzreq": "",
        "client_id": "client1",
        "code": access_grant,
        "code_used": False,
        "redirect_uri": "http://example.com/authz"
    }

    # Construct Access token request
    areq = AccessTokenRequest(code=access_grant,
                              redirect_uri="http://example.com/authz",
                              client_id="client2", client_secret="hemlighet",)

    print areq.to_dict()
    resp = provider.token_endpoint(request=areq.to_urlencoded())
    print resp.message
    atr = TokenErrorResponse().deserialize(resp.message, "json")
    print atr.keys()
    assert _eq(atr.keys(), ['error_description', 'error'])

if __name__ == "__main__":
    test_provider_authenticated()