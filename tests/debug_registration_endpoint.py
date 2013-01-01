from oic.oic.message import RegistrationResponseCARS
from oic.oic.message import RegistrationRequest
from pinit import provider_init
from pinit import BASE_ENVIRON
from pinit import start_response

__author__ = 'rohe0002'

server = provider_init

req = RegistrationRequest(type="client_associate")

req["application_type"] = "web"
req["application_name"] = "My super service"
req["redirect_uris"] = ["http://example.com/authz"]
req["contact"] = ["foo@example.com"]

environ = BASE_ENVIRON.copy()
environ["QUERY_STRING"] = req.to_urlencoded()

resp = server.registration_endpoint(environ, start_response)

print resp
regresp = RegistrationResponseCARS().deserialize(resp[0], "json")
print regresp.keys()
#assert _eq(regresp.keys(), ['client_secret', 'expires_at', 'client_id'])
