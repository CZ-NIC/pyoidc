# pylint: disable=missing-docstring,redefined-outer-name,no-self-use
import logging
import os
from urllib.parse import parse_qs
from urllib.parse import urlencode

import pytest
from mako.lookup import TemplateLookup
from testfixtures import LogCapture

from oic import rndstr
from oic.oauth2 import compact
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.http_util import Unauthorized

PASSWD = {"user": "hemligt"}

BASE_PATH = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_PATH, 'data/templates')
tl = TemplateLookup(directories=[TEMPLATE_DIR],
                    input_encoding='utf-8', output_encoding='utf-8')


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


@pytest.fixture
def srv():
    class Bunch(dict):
        def __init__(self, **kw):
            dict.__init__(self, kw)
            self.__dict__ = self

    return Bunch(symkey=rndstr(), seed=rndstr().encode("utf-8"),
                 iv=os.urandom(16), cookie_name="xyzxyz")


def create_return_form_env(user, password, query):
    _dict = {
        "login": user,
        "password": password,
        "query": query
    }

    return urlencode(_dict)


class TestUsernamePasswordMako(object):
    def test_authenticated_as_no_cookie(self):
        authn = UsernamePasswordMako(None, "login.mako", tl, PASSWD,
                                     "authorization_endpoint")
        res = authn.authenticated_as()
        assert res == (None, 0)

    def test_call(self):
        authn = UsernamePasswordMako(None, "login.mako", tl, PASSWD,
                                     "authorization_endpoint")
        resp = authn(query="QUERY")
        assert 'name="query" value="QUERY"' in resp.message
        assert 'name="login" value=""' in resp.message

    def test_authenticated_as(self, srv):
        form = create_return_form_env("user", "hemligt", "QUERY")

        authn = UsernamePasswordMako(srv, "login.mako", tl, PASSWD,
                                     "authorization_endpoint")
        response, success = authn.verify(compact(parse_qs(form)))

        headers = dict(response.headers)
        user, timestamp = authn.authenticated_as(headers["Set-Cookie"])
        assert user == {"uid": "user"}

    def test_verify(self, srv):
        form = create_return_form_env("user", "hemligt", "query=foo")

        authn = UsernamePasswordMako(srv, "login.mako", tl, PASSWD,
                                     "authorization_endpoint")
        with LogCapture(level=logging.DEBUG) as logcap:
            response, success = authn.verify(compact(parse_qs(form)))
        assert query_string_compare(response.message.split("?")[1],
                                    "query=foo&upm_answer=true")

        headers = dict(response.headers)
        assert headers["Set-Cookie"].startswith('xyzxyz=')
        expected = {u'query': u'query=foo', u'login': u'user',
                    u'password': '<REDACTED>'}
        # We have to use eval() here to avoid intermittent
        # failures from dict ordering
        assert eval(logcap.records[0].msg[7:-1]) == expected
        expected = {u'query': u'query=foo', u'login': u'user',
                    u'password': '<REDACTED>'}
        assert eval(logcap.records[1].msg[5:]) == expected
        assert logcap.records[2].msg == 'Password verification succeeded.'
        expected = {u'query': [u'foo'], 'upm_answer': 'true'}
        assert eval(logcap.records[3].msg[8:]) == expected

    def test_not_authenticated(self, srv):
        form = create_return_form_env("user", "hemligt", "QUERY")

        authn = UsernamePasswordMako(srv, "login.mako", tl, PASSWD,
                                     "authorization_endpoint")
        response, state = authn.verify(compact(parse_qs(form)))

        headers = dict(response.headers)
        kaka = headers["Set-Cookie"]

        kaka = kaka.replace("1", "x")
        assert authn.authenticated_as(kaka) == (None, 0)

    def test_verify_unauthorized(self, srv):
        form = create_return_form_env("user", "secret", "QUERY")

        authn = UsernamePasswordMako(srv, "login.mako", tl, PASSWD,
                                     "authorization_endpoint")
        response, state = authn.verify(parse_qs(form))
        assert isinstance(response, Unauthorized)
