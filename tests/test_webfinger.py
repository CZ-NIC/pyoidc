# pylint: disable=no-self-use,missing-docstring

import json

from oic.utils.webfinger import OIC_ISSUER
from oic.utils.webfinger import URINormalizer
from oic.utils.webfinger import WebFinger

__author__ = 'rolandh'

# examples provided by Nat Sakimura
EXAMPLE = {
    "example.com": "https://example.com",
    "example.com:8080": "https://example.com:8080",
    "example.com/path": "https://example.com/path",
    "example.com?query": "https://example.com?query",
    "example.com#fragment": "https://example.com",
    "example.com:8080/path?query#fragment":
        "https://example.com:8080/path?query",
    "http://example.com": "http://example.com",
    "http://example.com:8080": "http://example.com:8080",
    "http://example.com/path": "http://example.com/path",
    "http://example.com?query": "http://example.com?query",
    "http://example.com#fragment": "http://example.com",
    "http://example.com:8080/path?query#fragment":
        "http://example.com:8080/path?query",
    "nov@example.com": "acct:nov@example.com",
    "nov@example.com:8080": "https://nov@example.com:8080",
    "nov@example.com/path": "https://nov@example.com/path",
    "nov@example.com?query": "https://nov@example.com?query",
    "nov@example.com#fragment": "acct:nov@example.com",
    "nov@example.com:8080/path?query#fragment":
        "https://nov@example.com:8080/path?query",
    "acct:nov@matake.jp": "acct:nov@matake.jp",
    "acct:nov@example.com:8080": "acct:nov@example.com:8080",
    "acct:nov@example.com/path": "acct:nov@example.com/path",
    "acct:nov@example.com?query": "acct:nov@example.com?query",
    "acct:nov@example.com#fragment": "acct:nov@example.com",
    "acct:nov@example.com:8080/path?query#fragment":
        "acct:nov@example.com:8080/path?query",
    "mailto:nov@matake.jp": "mailto:nov@matake.jp",
    "mailto:nov@example.com:8080": "mailto:nov@example.com:8080",
    "mailto:nov@example.com/path": "mailto:nov@example.com/path",
    "mailto:nov@example.com?query": "mailto:nov@example.com?query",
    "mailto:nov@example.com#fragment": "mailto:nov@example.com",
    "mailto:nov@example.com:8080/path?query#fragment":
        "mailto:nov@example.com:8080/path?query",
    "localhost": "https://localhost",
    "localhost:8080": "https://localhost:8080",
    "localhost/path": "https://localhost/path",
    "localhost?query": "https://localhost?query",
    "localhost#fragment": "https://localhost",
    "localhost/path?query#fragment": "https://localhost/path?query",
    "nov@localhost": "acct:nov@localhost",
    "nov@localhost:8080": "https://nov@localhost:8080",
    "nov@localhost/path": "https://nov@localhost/path",
    "nov@localhost?query": "https://nov@localhost?query",
    "nov@localhost#fragment": "acct:nov@localhost",
    "nov@localhost/path?query#fragment": "https://nov@localhost/path?query",
    "tel:+810312345678": "tel:+810312345678",
    "device:192.168.2.1": "device:192.168.2.1",
    "device:192.168.2.1:8080": "device:192.168.2.1:8080",
    "device:192.168.2.1/path": "device:192.168.2.1/path",
    "device:192.168.2.1?query": "device:192.168.2.1?query",
    "device:192.168.2.1#fragment": "device:192.168.2.1",
    "device:192.168.2.1/path?query#fragment": "device:192.168.2.1/path?query",
}


class TestURINormalizer(object):
    def test_normalize(self):
        for key, val in EXAMPLE.items():
            _val = URINormalizer().normalize(key)
            assert val == _val


class TestWebFinger(object):
    def test_query_device(self):
        wf = WebFinger()
        query = wf.query(resource="device:p1.example.com")
        assert query == 'https://p1.example.com/.well-known/webfinger' \
                        '?resource=device%3Ap1.example.com'

    def test_query_rel(self):
        wf = WebFinger()
        query = wf.query("acct:bob@example.com",
                         ["http://webfinger.net/rel/profile-page", "vcard"])
        assert query == "https://example.com/.well-known/webfinger?resource" \
                        "=acct%3Abob%40example.com&rel=http%3A%2F%2Fwebfinger" \
                        ".net%2Frel%2Fprofile-page&rel=vcard"

    def test_query_acct(self):
        wf = WebFinger(OIC_ISSUER)
        query = wf.query("acct:carol@example.com")

        assert query == "https://example.com/.well-known/webfinger?resource" \
                        "=acct%3Acarol%40example.com&rel=http%3A%2F%2Fopenid" \
                        ".net%2Fspecs%2Fconnect%2F1.0%2Fissuer"

    def test_query_device_host_forced(self):
        wf = WebFinger()
        query = wf.query(resource="device:p1.example.com", host='forced.com')
        assert query == 'https://forced.com/.well-known/webfinger' \
                        '?resource=device%3Ap1.example.com'

    def test_query_rel_host_forced(self):
        wf = WebFinger()
        query = wf.query("acct:bob@example.com",
                         ["http://webfinger.net/rel/profile-page", "vcard"],
                         host='forced.com:3000')
        assert query == "https://forced.com:3000/.well-known/webfinger?resource" \
                        "=acct%3Abob%40example.com&rel=http%3A%2F%2Fwebfinger" \
                        ".net%2Frel%2Fprofile-page&rel=vcard"

    def test_query_acct_host_forced(self):
        wf = WebFinger(OIC_ISSUER)
        query = wf.query("http://example.com/carol", host='forced.co')

        assert query == "https://forced.co/.well-known/webfinger?resource" \
                        "=http%3A%2F%2Fexample.com%2Fcarol&rel=http%3A%2F%2Fopenid" \
                        ".net%2Fspecs%2Fconnect%2F1.0%2Fissuer"

    def test_wf4(self):
        EX0 = {
            "expires": "2012-11-16T19:41:35Z",
            "subject": "acct:bob@example.com",
            "aliases": [
                "http://www.example.com/~bob/"
            ],
            "properties": {
                "http://example.com/ns/role/": "employee"
            },
            "links": [
                {
                    "rel": "http://webfinger.net/rel/avatar",
                    "type": "image/jpeg",
                    "href": "http://www.example.com/~bob/bob.jpg"
                },
                {
                    "rel": "http://webfinger.net/rel/profile-page",
                    "href": "http://www.example.com/~bob/"
                },
                {
                    "rel": "blog",
                    "type": "text/html",
                    "href": "http://blogs.example.com/bob/",
                    "titles": {
                        "en-us": "The Magical World of Bob",
                        "fr": "Le monde magique de Bob"
                    }
                },
                {
                    "rel": "vcard",
                    "href": "https://www.example.com/~bob/bob.vcf"
                }
            ]
        }

        wf = WebFinger()
        jrd0 = wf.load(json.dumps(EX0))

        for link in jrd0["links"]:
            if link["rel"] == "blog":
                assert link["href"] == "http://blogs.example.com/bob/"
                break

    def test_extra_member_response(self):
        wf = WebFinger()
        resp = wf.response('acct:local@domain', 'https://example.com',
                           dummy='foo')

        # resp should be a JSON document

        _resp = json.loads(resp)
        assert _resp['dummy'] == 'foo'
