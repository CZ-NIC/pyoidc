from base64 import b64encode

import pytest

from oic.exception import FailedAuthentication
from oic.oic.message import AuthorizationRequest
from oic.utils.authn.client import get_client_id

CDB = {
    'number5': {'client_secret': 'drickyoughurt'},
    'token_client': {},
    'expired': {'client_secret': 'drickyoughurt', 'client_secret_expires_at': 1},
    'secret_token': 'token_client',
    'expired_token': 'expired',
}


class TestGetClientID(object):

    def setup_class(self):
        self.cdb = CDB.copy()

    def test_empty_authn_client_ok(self):
        bib = {'client_id': 'number5'}
        arq = AuthorizationRequest(**bib)
        assert get_client_id(self.cdb, arq, None) == 'number5'

    def test_empty_authn_client_missing(self):
        bib = {'client_id': 'missing'}
        arq = AuthorizationRequest(**bib)
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, arq, None)

    def test_empty_authn_empty_request(self):
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), None)

    def test_empty_authn_client_invalid(self):
        bib = {'client_id': 'expired'}
        arq = AuthorizationRequest(**bib)
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, arq, None)

    def test_wrong_authn(self):
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), 'mumbo jumbo')

    def test_basic_authn_client_ok(self):
        authn = 'Basic ' + b64encode(b'number5:drickyoughurt').decode()
        assert get_client_id(self.cdb, AuthorizationRequest(), authn)

    def test_basic_authn_client_missing(self):
        authn = 'Basic ' + b64encode(b'missing:drickyoughurt').decode()
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), authn)

    def test_basic_authn_client_wrongpass(self):
        authn = 'Basic ' + b64encode(b'number5:wrongpassword').decode()
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), authn)

    def test_basic_authn_client_invalid(self):
        authn = 'Basic ' + b64encode(b'expired:drickyoughurt').decode()
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), authn)

    def test_bearer_authn_client_ok(self):
        authn = 'Bearer secret_token'
        assert get_client_id(self.cdb, AuthorizationRequest(), authn) == 'token_client'

    def test_bearer_authn_client_missing(self):
        authn = 'Bearer wrong_token'
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), authn)

    def test_bearer_authn_client_invalid(self):
        authn = 'Bearer expired_token'
        with pytest.raises(FailedAuthentication):
            get_client_id(self.cdb, AuthorizationRequest(), authn)
