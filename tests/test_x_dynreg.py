from mako.lookup import TemplateLookup
from oic.utils.http_util import Response, NoContent, Unauthorized
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.client import BearerHeader
from oic.utils.authn.client import ClientSecretPost
from oic.utils.authn.client import ClientSecretBasic
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import Implicit

from oic.utils import sdb
from oic.oauth2.dynreg import Provider
from oic.oauth2.dynreg import RegistrationRequest
from oic.oauth2.dynreg import ClientInfoResponse
from oic.oauth2.dynreg import ClientRegistrationError

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


def test_provider_init():
    provider = Provider("pyoicserv", sdb.SessionDB(SERVER_INFO["issuer"]), CDB,
                        AUTHN_BROKER, AUTHZ,
                        verify_client, client_info_url="https://example.com/as")

    assert provider


def test_client_registration():
    provider = Provider("pyoicserv", sdb.SessionDB(SERVER_INFO["issuer"]), CDB,
                        AUTHN_BROKER, AUTHZ,
                        verify_client,
                        client_info_url="https://example.com/as/")

    request = RegistrationRequest(client_name="myself",
                                  redirect_uris=["https://example.com/rp"])

    resp = provider.registration_endpoint(request.to_json(), {})

    assert isinstance(resp, Response)

    _resp = ClientInfoResponse().from_json(resp.message)

    assert "client_id" in _resp


def test_client_registration_uri_error():
    args = {
        "redirect_uris": ["https://client.example.org/callback",
                          "https://client.example.org/callback2"],
        "client_name": "My Example Client",
        "client_name#ja-Jpan-JP":
            "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "read write dolphin",
        "logo_uri": "https://client.example.org/logo.png",
        "jwks_uri": "https://client.example.org/my_public_keys.jwks"
    }

    provider = Provider("pyoicserv", sdb.SessionDB("https://example.org/"),
                        CDB, AUTHN_BROKER, AUTHZ, verify_client,
                        client_info_url="https://example.com/as/")

    request = RegistrationRequest(**args)

    resp = provider.registration_endpoint(request.to_json(), {})

    assert isinstance(resp, Response)

    _resp = ClientRegistrationError().from_json(resp.message)

    assert "error" in _resp
    assert _resp["error"] == "invalid_client_metadata"


def test_client_registration_2():
    args = {
        "redirect_uris": ["https://client.example.org/callback",
                          "https://client.example.org/callback2"],
        "client_name": "My Example Client",
        "client_name#ja-Jpan-JP":
            "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "read write dolphin",
    }

    provider = Provider("pyoicserv", sdb.SessionDB("https://example.org/"),
                        CDB, AUTHN_BROKER, AUTHZ, verify_client,
                        client_info_url="https://example.com/as/",
                        client_authn_methods={
                            "client_secret_post": ClientSecretPost,
                            "client_secret_basic": ClientSecretBasic,
                            "bearer_header": BearerHeader})

    request = RegistrationRequest(**args)

    resp = provider.registration_endpoint(request.to_json(), {})

    assert isinstance(resp, Response)

    _resp = ClientInfoResponse().from_json(resp.message)

    assert "client_name#ja-Jpan-JP" in _resp.keys()
    assert "client_name" in _resp.keys()


def test_client_user_info_get():
    args = {
        "redirect_uris": ["https://client.example.org/callback",
                          "https://client.example.org/callback2"],
        "client_name": "My Example Client",
        "client_name#ja-Jpan-JP":
            "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "read write dolphin",
    }

    provider = Provider("pyoicserv", sdb.SessionDB("https://example.org/"),
                        CDB, AUTHN_BROKER, AUTHZ, verify_client,
                        client_info_url="https://example.com/as/",
                        client_authn_methods={
                            "client_secret_post": ClientSecretPost,
                            "client_secret_basic": ClientSecretBasic,
                            "bearer_header": BearerHeader})

    request = RegistrationRequest(**args)

    resp = provider.registration_endpoint(request.to_json(),
                                                 environ={})

    assert isinstance(resp, Response)

    _resp = ClientInfoResponse().from_json(resp.message)

    assert "client_name#ja-Jpan-JP" in _resp.keys()
    assert "client_name" in _resp.keys()

    resp = provider.client_info_endpoint(
        "",
        environ={"HTTP_AUTHORIZATION": "Bearer %s" % (
            _resp["registration_access_token"],)},
        query="client_id=%s" % _resp["client_id"])

    _resp_cir = ClientInfoResponse().from_json(resp.message)

    assert _resp == _resp_cir


def test_client_registration_update():
    args = {
        "redirect_uris": ["https://client.example.org/callback",
                          "https://client.example.org/callback2"],
        "client_name": "My Example Client",
        "client_name#ja-Jpan-JP":
            "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "read write dolphin",
    }

    provider = Provider("pyoicserv", sdb.SessionDB("https://example.org/"),
                        CDB, AUTHN_BROKER, AUTHZ, verify_client,
                        client_info_url="https://example.com/as/",
                        client_authn_methods={
                            "client_secret_post": ClientSecretPost,
                            "client_secret_basic": ClientSecretBasic,
                            "bearer_header": BearerHeader})

    request = RegistrationRequest(**args)

    resp = provider.registration_endpoint(request.to_json(),
                                                 environ={})

    assert isinstance(resp, Response)

    _resp = ClientInfoResponse().from_json(resp.message)

    assert "client_name#ja-Jpan-JP" in _resp.keys()
    assert "client_name" in _resp.keys()

    update = {
        "client_id": _resp["client_id"],
        "client_secret": _resp["client_secret"],
        "redirect_uris": ["https://client.example.org/callback",
                          "https://client.example.org/alt"],
        "scope": "read write dolphin",
        "grant_types": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_method": "client_secret_basic",
        "jwks_uri": "https://client.example.org/my_public_keys.jwks",
        "client_name": "My New Example",
        "client_name#fr": "Mon Nouvel Exemple",
    }

    update_req = RegistrationRequest(**update)

    resp = provider.client_info_endpoint(
        update_req.to_json(),
        environ={"HTTP_AUTHORIZATION": "Bearer %s" % (
            _resp["registration_access_token"],)},
        method="PUT",
        query="client_id=%s" % _resp["client_id"])

    _resp_up = ClientInfoResponse().from_json(resp.message)


def test_client_registration_delete():
    args = {
        "redirect_uris": ["https://client.example.org/callback",
                          "https://client.example.org/callback2"],
        "client_name": "My Example Client",
        "client_name#ja-Jpan-JP":
            "\u30AF\u30E9\u30A4\u30A2\u30F3\u30C8\u540D",
        "token_endpoint_auth_method": "client_secret_basic",
        "scope": "read write dolphin",
    }

    provider = Provider("pyoicserv", sdb.SessionDB(SERVER_INFO["issuer"]), CDB,
                        AUTHN_BROKER, AUTHZ,
                        verify_client,
                        client_info_url="https://example.com/as/",
                        client_authn_methods={
                            "client_secret_post": ClientSecretPost,
                            "client_secret_basic": ClientSecretBasic,
                            "bearer_header": BearerHeader})

    request = RegistrationRequest(**args)

    resp = provider.registration_endpoint(request.to_json(),
                                                 environ={})

    assert isinstance(resp, Response)

    _resp = ClientInfoResponse().from_json(resp.message)

    resp = provider.client_info_endpoint(
        "",
        environ={"HTTP_AUTHORIZATION": "Bearer %s" % (
            _resp["registration_access_token"],)},
        method="DELETE",
        query="client_id=%s" % _resp["client_id"])

    assert isinstance(resp, NoContent)

    # A read should fail

    resp = provider.client_info_endpoint(
        "",
        environ={"HTTP_AUTHORIZATION": "Bearer %s" % (
            _resp["registration_access_token"],)},
        query="client_id=%s" % _resp["client_id"])

    assert isinstance(resp, Unauthorized)

# -----------------------------------------------------------------------------

test_client_registration_delete()
