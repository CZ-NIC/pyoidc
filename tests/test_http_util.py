# pylint: disable=redefined-outer-name,missing-docstring
import datetime

import pytest

from oic.utils.http_util import CookieDealer
from oic.utils.http_util import Response
from oic.utils.http_util import cookie_parts
from oic.utils.http_util import getpath
from oic.utils.http_util import geturl
from oic.utils.http_util import parse_cookie

__author__ = 'roland'


class TestResponse(object):
    def test_response(self):
        response_header = ("X-Test", "foobar")
        message = "foo bar"

        def start_response(status, headers):
            assert status == "200 OK"
            assert response_header in headers

        resp = Response(message, headers=[response_header])
        result = resp({}, start_response)
        assert result == [message.encode('utf8')]

    def test_escaped(self):
        template = '%s'
        response_header = ("XSS-Test", "script")
        message = '<script>alert("hi");</script>'

        def start_response(status, headers):
            assert status == "200 OK"
            assert response_header in headers

        resp = Response(message=message, headers=[response_header], template=template)
        assert resp({}, start_response) == ['&lt;script&gt;alert("hi");&lt;/script&gt;'.encode('utf8')]


@pytest.fixture
def cookie_dealer():
    class DummyServer():
        def __init__(self):
            self.symkey = "0123456789012345"

    return CookieDealer(DummyServer())


class TestCookieDealer(object):
    def test_create_cookie_value(self, cookie_dealer):
        cookie_value = "Something to pass along"
        cookie_typ = "sso"
        cookie_name = "Foobar"

        kaka = cookie_dealer.create_cookie(cookie_value, cookie_typ,
                                           cookie_name)
        value, timestamp, typ = cookie_dealer.get_cookie_value(kaka[1],
                                                               "Foobar")

        assert (value, typ) == (cookie_value, cookie_typ)

    def test_delete_cookie(self, cookie_dealer):
        cookie_name = "Foobar"
        kaka = cookie_dealer.delete_cookie(cookie_name)
        cookie_expiration = kaka[1].split(";")[1].split("=")[1]

        now = datetime.datetime.utcnow()  #
        cookie_timestamp = datetime.datetime.strptime(
            cookie_expiration, "%a, %d-%b-%Y %H:%M:%S GMT")
        assert cookie_timestamp < now

    def test_per_cookie_iv_seed(self):
        def cookie_dealer():
            class Server():
                def __init__(self):
                    self.symkey = "0123456789012345"
                    self.cookie_name = "baz"
            return CookieDealer(Server())

        cd1 = cookie_dealer()

        assert cd1.srv is not None
        assert getattr(cd1.srv, 'seed', None) is None
        assert getattr(cd1.srv, 'iv', None) is None

        cookie1 = cd1.create_cookie("foo", "bar")
        seed1 = cd1.srv.seed
        iv1 = cd1.srv.iv

        cookie2 = cd1.create_cookie("foo", "bar")
        seed2 = cd1.srv.seed
        iv2 = cd1.srv.iv

        assert cookie1 != cookie2
        assert seed1 != seed2
        assert iv1 != iv2


def test_parse_cookie():
    kaka = ('pyoidc=bjmc::1463043535::upm|'
            '1463043535|18a201305fa15a96ce4048e1fbb03f7715f86499')
    seed = ''
    name = 'pyoidc'
    result = parse_cookie(name, seed, kaka)
    assert result == ('bjmc::1463043535::upm', '1463043535')


def test_cookie_parts():
    name = 'pyoidc'
    kaka = ('pyoidc=bjmc::1463043535::upm|'
            '1463043535|18a201305fa15a96ce4048e1fbb03f7715f86499')
    result = cookie_parts(name, kaka)
    assert result == ['bjmc::1463043535::upm',
                      '1463043535',
                      '18a201305fa15a96ce4048e1fbb03f7715f86499']


def test_geturl():
    environ = {
        "wsgi.url_scheme": "http",
        "SERVER_NAME": "example.com",
        "SERVER_PORT": "80",
        "SCRIPT_NAME": "/foo",
        "PATH_INFO": "/bar",
        "QUERY_STRING": "baz=xyz"
    }

    assert geturl(environ) == "http://example.com/foo/bar?baz=xyz"


def test_getpath():
    environ = {
        "SCRIPT_NAME": "/foo",
        "PATH_INFO": "/bar",
    }

    assert getpath(environ) == "/foo/bar"
