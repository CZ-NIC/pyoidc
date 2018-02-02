import json
from operator import itemgetter

import pytest
import responses

from oic.oauth2.exception import NoClientInfoReceivedError
from oic.utils.clientdb import DictClientDatabase
from oic.utils.clientdb import MDQClient


class TestDictClientDatabase(object):
    """Tests for DictClientDatabase."""

    def test_setitem(self):
        cdb = DictClientDatabase()
        cdb['client1'] = 'value'

        assert cdb.cdb == {'client1': 'value'}

    def test_getitem(self):
        cdb = DictClientDatabase()
        cdb['client1'] = 'value'

        assert cdb['client1'] == 'value'

    def test_getitem_missing(self):
        cdb = DictClientDatabase()
        with pytest.raises(KeyError):
            cdb['client2']

    def test_get_missing(self):
        cdb = DictClientDatabase()
        assert cdb.get('client') is None
        assert cdb.get('client', 'spam') == 'spam'

    def test_get(self):
        cdb = DictClientDatabase()
        cdb['client'] = 'value'

        assert cdb.get('client', 'spam') == 'value'

    def test_keys(self):
        cdb = DictClientDatabase()
        cdb['client1'] = 'spam'
        cdb['client2'] = 'eggs'

        assert set(cdb.keys()) == {'client1', 'client2'}

    def test_items(self):
        cdb = DictClientDatabase()
        cdb['client1'] = 'spam'
        cdb['client2'] = 'eggs'

        assert set(cdb.items()) == {('client1', 'spam'), ('client2', 'eggs')}

    def test_contains(self):
        cdb = DictClientDatabase()
        cdb['client1'] = 'spam'

        assert 'client1' in cdb
        assert 'client2' not in cdb

    def test_delete(self):
        cdb = DictClientDatabase()
        cdb['client1'] = 'spam'

        del cdb['client1']

        assert 'client1' not in cdb

    def test_len(self):
        cdb = DictClientDatabase()
        cdb['client1'] = 'spam'
        cdb['client2'] = 'eggs'

        assert len(cdb) == 2


class TestMDQClient(object):
    """Tests for MDQClient."""

    URL = "http://localhost/mdx/"

    @pytest.fixture(autouse=True)
    def create_client(self):
        self.md = MDQClient(TestMDQClient.URL)

    def test_get_existing_client(self):
        metadata = {"client_id": 'client1',
                    "client_secret": "abcd1234",
                    "redirect_uris": ["http://example.com/rp/authz_cb"]}
        url = TestMDQClient.URL + 'entities/client1'
        with responses.RequestsMock() as rsps:
            rsps.add(rsps.GET, url, body=json.dumps(metadata))
            result = self.md['client1']

        assert metadata == result

    def test_get_non_existing_client(self):
        url = TestMDQClient.URL + 'entities/client1'
        with responses.RequestsMock() as rsps:
            rsps.add(rsps.GET, url, status=404)
            with pytest.raises(NoClientInfoReceivedError):
                self.md['client1']

    def test_keys(self):
        url = TestMDQClient.URL + 'entities'
        metadata = [
            {'client_id': 'client1',
             'client_secret': 'secret',
             'redirect_uris': ['http://example.com']},
            {'client_id': 'client2',
             'client_secret': 'secret',
             'redirect_uris': ['http://ecample2.com']},
        ]
        with responses.RequestsMock() as rsps:
            rsps.add(rsps.GET, url, body=json.dumps(metadata))
            result = self.md.keys()

        assert {'client1', 'client2'} == set(result)

    def test_keys_error(self):
        url = TestMDQClient.URL + 'entities'
        with responses.RequestsMock() as rsps:
            rsps.add(rsps.GET, url, status=404)
            with pytest.raises(NoClientInfoReceivedError):
                self.md.keys()

    def test_items(self):
        url = TestMDQClient.URL + 'entities'
        metadata = [
            {'client_id': 'client1',
             'client_secret': 'secret',
             'redirect_uris': ['http://example.com']},
            {'client_id': 'client2',
             'client_secret': 'secret',
             'redirect_uris': ['http://ecample2.com']},
        ]
        with responses.RequestsMock() as rsps:
            rsps.add(rsps.GET, url, body=json.dumps(metadata))
            result = self.md.items()

        assert sorted(metadata, key=itemgetter('client_id')) == sorted(result, key=itemgetter('client_id'))

    def test_items_errors(self):
        url = TestMDQClient.URL + 'entities'
        with responses.RequestsMock() as rsps:
            rsps.add(rsps.GET, url, status=404)
            with pytest.raises(NoClientInfoReceivedError):
                self.md.items()
