# pylint: disable=redefined-outer-name,missing-docstring
import datetime

import pytest

from oic.utils.http_util import CookieDealer, Response

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
        assert result == [message]


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

        print(cookie_expiration)

        now = datetime.datetime.now()
        cookie_timestamp = datetime.datetime.strptime(cookie_expiration,
                                                      "%a, %d-%b-%Y %H:%M:%S GMT")
        assert cookie_timestamp < now
