from utils_for_tests import URLObject, url_compare

__author__ = "@maennelpaennel"


def test_utils_urlobject_init():
    url_1 = URLObject(host='host', resource='resource',
                      arguments=set(['arguments']))
    url_2 = URLObject(host='host', resource='resource',
                      arguments=set(['arguments']))
    assert url_1 == url_2


def test_utils_urlobject_set_by_string():
    url_1 = URLObject.create(
        'this_is_a_host/this_is_a_resource?followed_by=args&and_more=args')
    url_2 = URLObject(host='this_is_a_host', resource='this_is_a_resource',
                      arguments=set(['followed_by=args', 'and_more=args']))
    assert url_1 == url_2


def test_url_compare():
    # reorder query params is still the same url
    assert url_compare("http://example.com?baz=xyz&foo=bar",
                       "http://example.com?foo=bar&baz=xyz")
