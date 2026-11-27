"""PKCE (RFC 7636) with the Consumer classes: begin() sends the code_challenge, complete() the code_verifier."""

import hashlib
from urllib.parse import parse_qs, urlparse

import pytest
import responses
from jwkest import b64e

from oic.oauth2.consumer import Consumer as OauthConsumer
from oic.oic.consumer import Consumer as OicConsumer
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.session_backend import DictSessionBackend

AUTHORIZATION_ENDPOINT = "https://example.com/authorization"
TOKEN_ENDPOINT = "https://example.com/token"
SERVER_INFO = {
    "issuer": "https://example.com",
    "authorization_endpoint": AUTHORIZATION_ENDPOINT,
    "token_endpoint": TOKEN_ENDPOINT,
}
PKCE_CONFIG = {"code_challenge": {"method": "S256", "length": 64}}


def _s256(verifier):
    return b64e(hashlib.sha256(verifier.encode("ascii")).digest()).decode("ascii")


def _query(url):
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


def _add_token_response(rsps, state):
    rsps.add(
        responses.POST,
        TOKEN_ENDPOINT,
        content_type="application/json",
        json={"access_token": "token", "token_type": "Bearer", "state": state},
    )


def _token_request(rsps):
    return {k: v[0] for k, v in parse_qs(rsps.calls[-1].request.body).items()}


class OauthFlow:
    """Drive oic.oauth2.consumer.Consumer through begin() and complete()."""

    def __init__(self, config):
        self.config = config

    def consumer(self, session_db):
        return OauthConsumer(
            session_db,
            client_config={"client_id": "client_1", "config": dict(self.config)},
            server_info=SERVER_INFO,
            authz_page="/authz",
            response_type="code",
            scope=["openid"],
            flow_type="code",
        )

    def begin(self, consumer):
        return consumer.begin("https://rp.example.com", "https://rp.example.com/login")

    def complete(self, consumer, state):
        consumer.complete("code=code&state={}".format(state), state)


class OicFlow:
    """Drive oic.oic.consumer.Consumer through begin(), parse_authz() and complete()."""

    def __init__(self, config):
        self.config = config

    def consumer(self, session_db):
        client_config = {
            "client_id": "client_1",
            "client_authn_method": CLIENT_AUTHN_METHOD,
            "config": dict(self.config),
        }
        consumer = OicConsumer(
            session_db,
            {"authz_page": "authz", "scope": ["openid"], "response_type": "code"},
            client_config,
            SERVER_INFO,
        )
        consumer.authorization_endpoint = AUTHORIZATION_ENDPOINT
        consumer.token_endpoint = TOKEN_ENDPOINT
        consumer.client_secret = "hemlig"
        return consumer

    def begin(self, consumer):
        return consumer.begin(path="https://rp.example.com")

    def complete(self, consumer, state):
        consumer.parse_authz(query="code=code&state={}".format(state))
        consumer.complete(state)


@pytest.fixture(params=[OauthFlow, OicFlow], ids=["oauth2", "oic"])
def flow_cls(request):
    return request.param


@pytest.fixture
def flow(flow_cls):
    """A Consumer flow with PKCE switched on in the client configuration."""
    return flow_cls(PKCE_CONFIG)


def test_begin_sends_code_challenge(flow):
    consumer = flow.consumer(DictSessionBackend())

    _, location = flow.begin(consumer)

    authz_request = _query(location)
    assert authz_request["code_challenge_method"] == "S256"
    assert "code_challenge" in authz_request


def test_complete_sends_matching_code_verifier(flow):
    consumer = flow.consumer(DictSessionBackend())
    state, location = flow.begin(consumer)

    with responses.RequestsMock() as rsps:
        _add_token_response(rsps, state)
        flow.complete(consumer, state)
        token_request = _token_request(rsps)

    assert _s256(token_request["code_verifier"]) == _query(location)["code_challenge"]


def test_complete_in_another_instance_with_shared_session_db(flow):
    # The Consumers keep their state in the session database, so another instance can complete the flow
    session_db = DictSessionBackend()
    state, location = flow.begin(flow.consumer(session_db))
    other = flow.consumer(session_db)

    with responses.RequestsMock() as rsps:
        _add_token_response(rsps, state)
        flow.complete(other, state)
        token_request = _token_request(rsps)

    assert _s256(token_request["code_verifier"]) == _query(location)["code_challenge"]


def test_no_pkce_without_configuration(flow_cls):
    flow = flow_cls({})
    consumer = flow.consumer(DictSessionBackend())
    state, location = flow.begin(consumer)

    with responses.RequestsMock() as rsps:
        _add_token_response(rsps, state)
        flow.complete(consumer, state)
        token_request = _token_request(rsps)

    assert "code_challenge" not in _query(location)
    assert "code_verifier" not in token_request
