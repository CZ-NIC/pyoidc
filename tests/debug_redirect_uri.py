from oic.oic.message import RegistrationRequest, AuthorizationRequest
from oic.oic.provider import Provider

__author__ = 'rohe0002'

provider = Provider("FOO", {}, {}, None, None)

environ = {}
def start_response(stat, head):
    return [""]

rr = RegistrationRequest(type="client_associate",
            redirect_uris=["http://example.org/cb"])

registration_req = rr.to_urlencoded()

provider.registration_endpoint(environ, start_response,
                               query=registration_req)

areq = AuthorizationRequest(redirect_uri="http://example.org/cb",
                        client_id=provider.cdb.keys()[0])

assert provider._verify_redirect_uri(areq) == None

areq = AuthorizationRequest(redirect_uri="http://example.org/cb/foo",
                            client_id=provider.cdb.keys()[0])

assert provider._verify_redirect_uri(areq) == None

areq = AuthorizationRequest(redirect_uri="http://example.org/cb?foo=bar",
                            client_id=provider.cdb.keys()[0])

assert provider._verify_redirect_uri(areq) == None

provider2 = Provider("FOOP", {}, {}, None, None)

environ = {}
def start_response(stat, head):
    return [""]

rr = RegistrationRequest(type="client_associate",
                         redirect_uris=["http://example.org/cb?foo=bar"])

registration_req = rr.to_urlencoded()

provider2.registration_endpoint(environ, start_response,
                               query=registration_req)

areq = AuthorizationRequest(redirect_uri="http://example.org/cb",
                            client_id=provider2.cdb.keys()[0])

assert provider2._verify_redirect_uri(areq) != None

areq = AuthorizationRequest(redirect_uri="http://example.org/cb/foo",
                            client_id=provider2.cdb.keys()[0])

assert provider2._verify_redirect_uri(areq) != None

areq = AuthorizationRequest(redirect_uri="http://example.org/cb?foo=bar",
                            client_id=provider2.cdb.keys()[0])

assert provider2._verify_redirect_uri(areq) == None

areq = AuthorizationRequest(redirect_uri="http://example.org/cb?foo=bar&got=you",
                            client_id=provider2.cdb.keys()[0])

assert provider2._verify_redirect_uri(areq) == None
