"""PKCE (RFC 7636) on the client side: a client that sends a code_challenge must send the matching code_verifier."""

import hashlib
from collections.abc import MutableMapping
from urllib.parse import parse_qs, urlparse

import pytest
import responses
from jwkest import b64e
from pydantic import ValidationError

from oic import unreserved
from oic.extension.client import Client as ExtensionClient
from oic.oic import Client as OicClient
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.settings import OauthClientSettings, OicClientSettings

AUTHORIZATION_ENDPOINT = "https://example.com/authorization"
TOKEN_ENDPOINT = "https://example.com/token"
REDIRECT_URI = "https://example.com/redirect"
PKCE_CONFIG = {"code_challenge": {"method": "S256", "length": 64}}


def _make_client(client_cls, config, **kwargs):
    client = client_cls(client_id="client_1", client_authn_method=CLIENT_AUTHN_METHOD, config=config, **kwargs)
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


def _callback_location(state):
    return "{}?code=code-{}&state={}".format(REDIRECT_URI, state, state)


def _handle_callback(client, state):
    """Parse the authorization response, as the redirect_uri handler would."""
    response_cls = client.message_factory.get_response_type("authorization_endpoint")
    client.parse_response(response_cls, _callback_location(state), sformat="urlencoded")


def _authorize(client, rsps, state, request_args=None):
    """Run the authorization request and feed the redirect back; return the authorization request params."""
    rsps.add(responses.GET, AUTHORIZATION_ENDPOINT, status=302, headers={"location": _callback_location(state)})
    if request_args is None:
        request_args = {"response_type": ["code"], "scope": ["openid"]}
    client.do_authorization_request(state=state, request_args=request_args)

    _handle_callback(client, state)
    return _query(rsps.calls[-1].request.url)


def _token(client, rsps, state, request_args=None, status=200, body=None):
    """Run the token request; return the token request params."""
    if body is None:
        body = {"token_type": "Bearer", "access_token": "token", "state": state}
    rsps.add(responses.POST, TOKEN_ENDPOINT, status=status, content_type="application/json", json=body)
    client.do_access_token_request(state=state, request_args=request_args)
    return {k: v[0] for k, v in parse_qs(rsps.calls[-1].request.body).items()}


class VerifierStore(MutableMapping):
    """A store that is not a dict, as a persistent (database, cache) backend would be."""

    def __init__(self):
        self.data = {}

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def __delitem__(self, key):
        del self.data[key]

    def __iter__(self):
        return iter(self.data)

    def __len__(self):
        return len(self.data)


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


# --- a pluggable store for the code verifiers, set through the client settings ---

SETTINGS_CLS = {ExtensionClient: OauthClientSettings, OicClient: OicClientSettings}


def _settings(client_cls, **kwargs):
    return SETTINGS_CLS[client_cls](**kwargs)


@pytest.fixture(params=["default", "custom"])
def store_kwargs(request, client_cls):
    """Client constructor kwargs for the default (in-memory) and a custom verifier store."""
    if request.param == "default":
        return {}
    return {"settings": _settings(client_cls, code_verifier_store=VerifierStore())}


@pytest.mark.parametrize("settings_cls", [OauthClientSettings, OicClientSettings])
def test_settings_keep_the_store_object(settings_cls):
    # pydantic must not replace the store with a copy, or instances sharing it would each get their own
    store = VerifierStore()

    assert settings_cls(code_verifier_store=store).code_verifier_store is store


def test_store_not_taken_from_environment(monkeypatch):
    # A store is a live object; a JSON value from the environment must not become one
    monkeypatch.setenv("CODE_VERIFIER_STORE", '{"state0": "verifier"}')

    with pytest.raises(ValidationError):
        OauthClientSettings()


def test_custom_store_receives_verifier(client_cls):
    store = VerifierStore()
    client = _make_client(client_cls, dict(PKCE_CONFIG), settings=_settings(client_cls, code_verifier_store=store))

    with responses.RequestsMock() as rsps:
        authz_request = _authorize(client, rsps, "state0")

    assert client.code_verifiers is store
    assert _s256(store["state0"]) == authz_request["code_challenge"]


def test_custom_store_shared_between_instances(client_cls):
    # One instance sends the authorization request, another one handles the callback
    settings = _settings(client_cls, code_verifier_store=VerifierStore())
    first = _make_client(client_cls, dict(PKCE_CONFIG), settings=settings)
    second = _make_client(client_cls, dict(PKCE_CONFIG), settings=settings)

    with responses.RequestsMock() as rsps:
        authz_request = _authorize(first, rsps, "state0")
        _handle_callback(second, "state0")
        token_request = _token(second, rsps, "state0")

    assert _s256(token_request["code_verifier"]) == authz_request["code_challenge"]


def test_shared_settings_without_store_keep_verifiers_per_instance(client_cls):
    # Without a store in the settings, each client keeps its own in-memory store
    settings = _settings(client_cls)
    first = _make_client(client_cls, dict(PKCE_CONFIG), settings=settings)
    second = _make_client(client_cls, dict(PKCE_CONFIG), settings=settings)

    with responses.RequestsMock() as rsps:
        _authorize(first, rsps, "state0")

    assert "state0" in first.code_verifiers
    assert "state0" not in second.code_verifiers


def test_verifier_removed_after_successful_token_response(client_cls, store_kwargs):
    # The code is single-use, so the verifier is no longer needed; persistent stores must not grow
    client = _make_client(client_cls, dict(PKCE_CONFIG), **store_kwargs)

    with responses.RequestsMock() as rsps:
        _authorize(client, rsps, "state0")
        _token(client, rsps, "state0")

    assert "state0" not in client.code_verifiers


def test_verifier_kept_after_error_response(client_cls, store_kwargs):
    # A failed token request may be retried, so the verifier stays
    client = _make_client(client_cls, dict(PKCE_CONFIG), **store_kwargs)

    with responses.RequestsMock() as rsps:
        _authorize(client, rsps, "state0")
        _token(client, rsps, "state0", status=400, body={"error": "invalid_request"})

    assert "state0" in client.code_verifiers


def test_reset_keeps_custom_store(client_cls):
    # The store may be shared with other instances, so one instance's reset must not wipe it
    store = VerifierStore()
    store["other-state"] = "verifier"
    client = _make_client(client_cls, dict(PKCE_CONFIG), settings=_settings(client_cls, code_verifier_store=store))

    client.reset()

    assert client.code_verifiers is store
    assert store["other-state"] == "verifier"


def test_reset_clears_default_store(client):
    client.code_verifiers["state0"] = "verifier"

    client.reset()

    assert "state0" not in client.code_verifiers
