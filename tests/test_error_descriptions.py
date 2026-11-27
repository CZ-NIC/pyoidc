"""error_description must not disclose internal details (tracebacks, foreign exception text).

RFC 6749, section 5.2 defines error_description as a hint for the client developer. Internal
details belong in the server log, not in a response that anyone can trigger.
"""

import json

from oic.oic.message import RegistrationRequest

# Looks like what a library exception might carry: an internal path and a host name
INTERNAL_DETAIL = 'internal detail at "C:\\srv\\oidc\\keys.py" via db01.internal'


def _boom(*args, **kwargs):
    raise RuntimeError(INTERNAL_DETAIL)


def _assert_no_internal_details(resp):
    assert "internal detail" not in resp.message
    assert "db01.internal" not in resp.message
    assert "Traceback" not in resp.message
    assert "RuntimeError" not in resp.message


def test_providerinfo_endpoint_does_not_return_traceback(provider, monkeypatch):
    # On an unexpected failure the endpoint tries to send the traceback lines as error_description.
    # Today that raises TooManyValues (HTTP 500), so the error handler itself is broken; the fix must
    # return a proper error response without the traceback.
    monkeypatch.setattr(provider, "create_providerinfo", _boom)

    resp = provider.providerinfo_endpoint()

    _assert_no_internal_details(resp)


def test_authorization_endpoint_does_not_return_exception_text(provider, monkeypatch):
    monkeypatch.setattr(provider.server, "parse_authorization_request", _boom)

    resp = provider.authorization_endpoint(request="response_type=code&client_id=client1")

    assert resp.status_code == 400
    assert json.loads(resp.message)["error"] == "invalid_request"
    _assert_no_internal_details(resp)


def test_registration_key_loading_does_not_return_exception_text(provider, monkeypatch):
    provider.cdb["client1"] = {"client_id": "client1"}
    monkeypatch.setattr(provider.keyjar, "load_keys", _boom)
    request = RegistrationRequest(jwks_uri="https://client.example.com/jwks.json")

    resp = provider.do_client_registration(request, "client1")

    assert resp.status_code == 500
    assert json.loads(resp.message)["error"] == "invalid_configuration_parameter"
    _assert_no_internal_details(resp)
