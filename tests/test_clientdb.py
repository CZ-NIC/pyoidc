# pylint: disable=missing-docstring

import json

import httpretty
import pytest
import requests

from oic.oauth2.exception import NoClientInfoReceivedError
from oic.utils.clientdb import MDQClient


class TestMDQClient(object):
    URL = "http://localhost/mdx"
    CLIENT_ID = "client1"
    MDX_URL = URL + "/entities/" + CLIENT_ID

    @pytest.fixture(autouse=True)
    def create_client(self):
        self.md = MDQClient(TestMDQClient.URL)

    @httpretty.activate
    def test_get_existing_client(self):
        metadata = {"client_id": TestMDQClient.CLIENT_ID,
                    "client_secret": "abcd1234",
                    "redirect_uris": ["http://example.com/rp/authz_cb"]}
        response_body = json.dumps(metadata)

        httpretty.register_uri(httpretty.GET,
                               TestMDQClient.MDX_URL.format(
                                   client_id=TestMDQClient.CLIENT_ID),
                               body=response_body,
                               content_type="application/json")

        result = self.md[TestMDQClient.CLIENT_ID]
        assert metadata == result

    @httpretty.activate
    def test_get_non_existing_client(self):
        httpretty.register_uri(httpretty.GET,
                               TestMDQClient.MDX_URL.format(
                                   client_id=TestMDQClient.CLIENT_ID),
                               status=404)

        with pytest.raises(NoClientInfoReceivedError):
            self.md[TestMDQClient.CLIENT_ID]  # pylint: disable=pointless-statement
