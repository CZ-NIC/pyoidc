# pylint: disable=missing-docstring

from utils_for_tests import url_compare


def test_url_compare():
    # reorder query params is still the same url
    assert url_compare("http://example.com?baz=xyz&foo=bar",
                       "http://example.com?foo=bar&baz=xyz")
