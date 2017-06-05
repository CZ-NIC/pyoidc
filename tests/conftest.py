"""Pytest fixtures for testing."""

import pytest

from oic.oic.provider import Provider
from oic.utils.authn.client import verify_client
from oic.utils.authz import AuthzHandling
from oic.utils.sdb import SessionDB


@pytest.fixture
def provider():
    issuer = "https://op.foo.com"
    client_db = {}
    session_db = SessionDB(issuer),
    verification_function = verify_client
    authz_handler = AuthzHandling()
    symkey = None
    user_info_store = None
    authn_broker = None
    return Provider(
        issuer,
        session_db,
        client_db,
        authn_broker,
        user_info_store,
        authz_handler,
        verification_function,
        symkey
    )
