from oic.extension.device_flow import AuthorizationRequest, DeviceFlowClient, DeviceFlowServer, TokenRequest
from oic.oauth2 import Client, Server


def test_device_flow():
    _client = Client()
    cli = DeviceFlowClient(_client)

    _server = Server()
    srv = DeviceFlowServer(_server)

    # init
    req = AuthorizationRequest(client_id=cli.host.client_id, response_type="device_code")

    resp = srv.device_endpoint(req)

    # Polling

    req2 = TokenRequest(
        grant_type="urn:ietf:params:oauth:grant-type:device_code",
        device_code=resp["device_dode"],
        client_id=cli.host.client_id,
    )

    resp = srv.token_endpoint(req2)

    # Authorization Pending

    # Do Authorization
