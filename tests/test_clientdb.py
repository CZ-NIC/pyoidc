import unittest

import httpretty
import jwkest

from oic.utils.clientdb import MDXClient, NoClientInfoReceived


class TestMDXClient(unittest.TestCase):
    URL = "http://localhost/mdx"
    CLIENT_ID = "client1"
    MDX_URL = URL + "/clients/" + CLIENT_ID

    def setUp(self):
        self.md = MDXClient(TestMDXClient.URL)

    @httpretty.activate
    def test_get_existing_client(self):
        metadata = {"client_id": TestMDXClient.CLIENT_ID,
                    "client_secret": "abcd1234",
                    "redirect_uris": ["http://example.com/rp/authz_cb"]}
        response_body = jwkest.pack(metadata)

        httpretty.register_uri(httpretty.GET,
                               TestMDXClient.MDX_URL.format(client_id=TestMDXClient.CLIENT_ID),
                               body=response_body,
                               content_type="application/json")

        result = self.md[TestMDXClient.CLIENT_ID]
        self.assertEqual(metadata, result)


    @httpretty.activate
    def test_get_non_existing_client(self):
        httpretty.register_uri(httpretty.GET,
                               TestMDXClient.MDX_URL.format(client_id=TestMDXClient.CLIENT_ID),
                               status=404)

        self.assertRaises(NoClientInfoReceived, lambda: self.md[TestMDXClient.CLIENT_ID])