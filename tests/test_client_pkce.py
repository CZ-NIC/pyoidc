"""PKCE (RFC 7636) on the client side: a client that sends a code_challenge must send the matching code_verifier."""

import hashlib
from urllib.parse import parse_qs, urlparse

import pytest
import responses
from jwkest import b64e

from oic import unreserved
from oic.extension.client import Client as ExtensionClient
from oic.oic import Client as OicClient
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

AUTHORIZATION_ENDPOINT = "https://example.com/authorization"
TOKEN_ENDPOINT = "https://example.com/token"
REDIRECT_URI = "https://example.com/redirect"
PKCE_CONFIG = {"code_challenge": {"method": "S256", "length": 64}}


def _make_client(client_cls, config):
    client = client_cls(client_id="client_1", client_authn_method=CLIENT_AUTHN_METHOD, config=config)
    client.client_secret = "abcdefghijklmnop"
    client.redirect_uris = [REDIRECT_URI]
    client.authorization_endpoint = AUTHORIZATION_ENDPOINT
    client.token_endpoint = TOKEN_ENDPOINT
    return client


@pytest.fixture(params=[ExtensionClient, OicClient], ids=["extension", "oic"])
def client_cls(request):
    return request.param


@pytest.fixture
def client(client_cls):
    """A client with PKCE switched on in its configuration."""
    return _make_client(client_cls, dict(PKCE_CONFIG))


@pytest.fixture
def plain_client(client_cls):
    """A client without PKCE in its configuration."""
    return _make_client(client_cls, {})


def _query(url):
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def _authorize(client, rsps, state, request_args=None):
    """Run the authorization request and feed the redirect back; return the authorization request params."""
    location = "{}?code=code-{}&state={}".format(REDIRECT_URI, state, state)
    rsps.add(responses.GET, AUTHORIZATION_ENDPOINT, status=302, headers={"location": location})
    if request_args is None:
        request_args = {"response_type": ["code"], "scope": ["openid"]}
    client.do_authorization_request(state=state, request_args=request_args)

    response_cls = client.message_factory.get_response_type("authorization_endpoint")
    client.parse_response(response_cls, location, sformat="urlencoded")
    return _query(rsps.calls[-1].request.url)


def _token(client, rsps, state, request_args=None):
    """Run the token request; return the token request params."""
    rsps.add(
        responses.POST,
        TOKEN_ENDPOINT,
        content_type="application/json",
        json={"token_type": "Bearer", "access_token": "token", "state": state},
    )
    client.do_access_token_request(state=state, request_args=request_args)
    return {k: v[0] for k, v in parse_qs(rsps.calls[-1].request.body).items()}


def _s256(verifier):
    return b64e(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii")


def test_authorization_request_sends_code_challenge(client):
    with responses.RequestsMock() as rsps:
        authz_request = _authorize(client, rsps, "state0")

    assert authz_request["code_challenge_method"] == "S256"
    assert "code_challenge" in authz_request


def test_do_authorization_request_returns_response(client):
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, AUTHORIZATION_ENDPOINT, status=302, headers={"location": REDIRECT_URI})
        resp = client.do_authorization_request(
            state="state0", request_args={"response_type": ["code"], "scope": ["openid"]}
        )

    assert resp is not None
    assert resp.status_code == 302


def test_authorization_request_without_request_args(client):
    with responses.RequestsMock() as rsps:
        rsps.add(responses.GET, AUTHORIZATION_ENDPOINT, status=302, headers={"location": REDIRECT_URI})
        client.do_authorization_request(state="state0")
        authz_request = _query(rsps.calls[-1].request.url)

    assert "code_challenge" in authz_request


def test_access_token_request_sends_matching_code_verifier(client):
    with responses.RequestsMock() as rsps:
        authz_request = _authorize(client, rsps, "state0")
        token_request = _token(client, rsps, "state0")

    assert "code_verifier" in token_request
    assert _s256(token_request["code_verifier"]) == authz_request["code_challenge"]


def test_code_verifier_is_kept_per_state(client):
    with responses.RequestsMock() as rsps:
        authz_a = _authorize(client, rsps, "state-a")
        authz_b = _authorize(client, rsps, "state-b")
        token_b = _token(client, rsps, "state-b")
        token_a = _token(client, rsps, "state-a")

    assert authz_a["code_challenge"] != authz_b["code_challenge"]
    assert _s256(token_a["code_verifier"]) == authz_a["code_challenge"]
    assert _s256(token_b["code_verifier"]) == authz_b["code_challenge"]


def test_no_code_verifier_without_pkce(plain_client):
    with responses.RequestsMock() as rsps:
        authz_request = _authorize(plain_client, rsps, "state0")
        token_request = _token(plain_client, rsps, "state0")

    assert "code_challenge" not in authz_request
    assert "code_verifier" not in token_request


def test_manual_pkce_still_works(plain_client):
    # Without the configuration switch, the caller can handle PKCE by hand
    verifier = unreserved(64)
    with responses.RequestsMock() as rsps:
        authz_request = _authorize(
            plain_client,
            rsps,
            "state0",
            request_args={
                "response_type": ["code"],
                "scope": ["openid"],
                "code_challenge": _s256(verifier),
                "code_challenge_method": "S256",
            },
        )
        token_request = _token(plain_client, rsps, "state0", request_args={"code_verifier": verifier})

    assert authz_request["code_challenge"] == _s256(verifier)
    assert token_request["code_verifier"] == verifier
