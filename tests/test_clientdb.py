import json
import unittest

import httpretty
import pytest

from oic.utils.clientdb import MDQClient, NoClientInfoReceived


class TestMDQClient(unittest.TestCase):
    URL = "http://localhost/mdx"
    CLIENT_ID = "client1"
    MDX_URL = URL + "/entities/" + CLIENT_ID

    def setUp(self):
        self.md = MDQClient(TestMDQClient.URL)

    @httpretty.activate
    def test_get_existing_client(self):
        metadata = {"client_id": TestMDQClient.CLIENT_ID,
                    "client_secret": "abcd1234",
                    "redirect_uris": ["http://example.com/rp/authz_cb"]}
        response_body = json.dumps(metadata)

        httpretty.register_uri(httpretty.GET,
                               TestMDQClient.MDX_URL.format(client_id=TestMDQClient.CLIENT_ID),
                               body=response_body,
                               content_type="application/json")

        result = self.md[TestMDQClient.CLIENT_ID]
        assert metadata == result


    @httpretty.activate
    def test_get_non_existing_client(self):
        httpretty.register_uri(httpretty.GET,
                               TestMDQClient.MDX_URL.format(client_id=TestMDQClient.CLIENT_ID),
                               status=404)

        with pytest.raises(NoClientInfoReceived):
            self.md[TestMDQClient.CLIENT_ID]