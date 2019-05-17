"""Pytest fixtures for testing."""
from typing import Any  # noqa
from typing import Dict  # noqa

import pytest

from oic.oic.provider import Provider
from oic.utils.authn.client import verify_client
from oic.utils.authz import AuthzHandling
from oic.utils.sdb import create_session_db


@pytest.fixture
def session_db_factory():
    def fac(issuer):
        return create_session_db(issuer,
                                 secret='supersecret', password='badpassword')
    return fac


@pytest.fixture
def session_db(session_db_factory):
    return session_db_factory("https://op.example.com")


@pytest.fixture
def fake_oic_server(session_db_factory):
    from tests.fakeoicsrv import MyFakeOICServer

    def fac(name):
        return MyFakeOICServer(name, session_db_factory=session_db_factory)
    return fac


@pytest.fixture
def mitm_server(session_db_factory):
    from tests.mitmsrv import MITMServer

    def fac(name):
        return MITMServer(name, session_db_factory=session_db_factory)
    return fac


@pytest.fixture
def provider(session_db):
    issuer = "https://op.example.com"
    client_db = {}  # type: Dict[str, Any]
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
