from oic.extension.device_flow import AuthorizationRequest
from oic.extension.device_flow import DeviceFlowClient
from oic.extension.device_flow import DeviceFlowServer
from oic.extension.device_flow import TokenRequest
from oic.oauth2 import Client
from oic.oauth2 import Server


def test_device_flow():
    _client = Client()
    cli = DeviceFlowClient(_client)

    _server = Server()
    srv = DeviceFlowServer(_server)

    # init
    req = AuthorizationRequest(client_id=cli.host.client_id,
                               response_type='device_code')

    resp = srv.device_endpoint(req)

    # Polling

    req2 = TokenRequest(
        grant_type="urn:ietf:params:oauth:grant-type:device_code",
        device_code=resp['device_dode'], client_id=cli.host.client_id)

    resp = srv.token_endpoint(req2)

    # Authorization Pending

    # Do Authorization
