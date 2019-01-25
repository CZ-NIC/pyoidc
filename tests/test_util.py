from http.cookiejar import FileCookieJar
from http.cookiejar import http2time  # type: ignore
from http.cookies import SimpleCookie
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest

from oic.exception import UnSupported
from oic.oauth2 import util
from oic.oic import AuthorizationRequest
from oic.oic.message import AccessTokenRequest
from oic.utils.template_render import TemplateException
from oic.utils.template_render import inputs
from oic.utils.template_render import render_template

__author__ = 'DIRG'


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


def url_compare(url1, url2):
    url1 = urlparse(url1)
    url2 = urlparse(url2)

    if url1.scheme != url2.scheme:
        return False
    if url1.netloc != url2.netloc:
        return False
    if url1.path != url2.path:
        return False
    if not query_string_compare(url1.query, url2.query):
        return False
    if not query_string_compare(url1.fragment, url2.fragment):
        return False

    return True


def test_get_or_post():
    uri = u'https://localhost:8092/authorization'
    method = 'GET'
    values = {'acr_values': 'PASSWORD',
              'state': 'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
              'redirect_uri': 'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
              'response_type': 'code', 'client_id': 'ok8tx7ulVlNV',
              'scope': 'openid profile email address phone'}
    request = AuthorizationRequest(**values)

    path, body, ret_kwargs = util.get_or_post(uri, method, request)

    assert url_compare(path,
                       u"https://localhost:8092/authorization?acr_values=PASSWORD&state=urn%3A"
                       "uuid%3A92d81fb3-72e8-4e6c-9173-c360b782148a&"
                       "redirect_uri=https%3A%2F%2Flocalhost%3A8666%2F919D3F697FDAAF138124B83E09ECB0B7&"
                       "response_type=code&client_id=ok8tx7ulVlNV&scope=openid+profile+email+address+phone")
    assert not body
    assert not ret_kwargs

    method = 'POST'
    uri = u'https://localhost:8092/token'
    values = {
        'redirect_uri': 'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
        'code': 'Je1iKfPN1vCiN7L43GiXAuAWGAnm0mzA7QIjl/YLBBZDB9wefNExQlLDUIIDM2rT'
                '2t+gwuoRoapEXJyY2wrvg9cWTW2vxsZU+SuWzZlMDXc=',
        'grant_type': 'authorization_code'}
    request = AccessTokenRequest(**values)
    kwargs = {'scope': '',
              'state': 'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
              'authn_method': 'client_secret_basic', 'key': [],
              'headers': {
                  'Authorization': 'Basic b2s4dHg3dWxWbE5WOjdlNzUyZDU1MTc0NzA0NzQzYjZiZWJk'
                                   'YjU4ZjU5YWU3MmFlMGM5NDM4YTY1ZmU0N2IxMDA3OTM1'}
              }

    path, body, ret_kwargs = util.get_or_post(uri, method, request, **kwargs)

    assert path == u'https://localhost:8092/token'
    assert url_compare("http://test/#{}".format(body),
                       'http://test/#code=Je1iKfPN1vCiN7L43GiXAuAWGAnm0mzA7QIjl%2FYLBBZDB9wefNExQlLDUIIDM2rT2t%2BgwuoR'
                       'oapEXJyY2wrvg9cWTW2vxsZU%2BSuWzZlMDXc%3D&grant_type=authorization_code&redirect_uri=https%3A%2'
                       'F%2Flocalhost%3A8666%2F919D3F697FDAAF138124B83E09ECB0B7')
    assert ret_kwargs == {'scope': '',
                          'state': 'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
                          'authn_method': 'client_secret_basic', 'key': [],
                          'headers': {
                              'Content-Type': 'application/x-www-form-urlencoded',
                              'Authorization': 'Basic b2s4dHg3dWxWbE5WOjdlNzUyZDU1MTc0NzA0NzQzYjZiZWJkYjU4ZjU5YWU3MmFl'
                                               'MGM5NDM4YTY1ZmU0N2IxMDA3OTM1'}}

    method = 'UNSUPORTED'
    with pytest.raises(UnSupported):
        util.get_or_post(uri, method, request, **kwargs)


def test_get_or_post_with_qp():
    uri = u'https://localhost:8092/authorization?test=testslice'
    method = 'GET'
    values = {'acr_values': 'PASSWORD',
              'state': 'urn:uuid:92d81fb3-72e8-4e6c-9173-c360b782148a',
              'redirect_uri': 'https://localhost:8666/919D3F697FDAAF138124B83E09ECB0B7',
              'response_type': 'code', 'client_id': 'ok8tx7ulVlNV',
              'scope': 'openid profile email address phone'}
    request = AuthorizationRequest(**values)

    path, body, ret_kwargs = util.get_or_post(uri, method, request)

    assert url_compare(path,
                       u"https://localhost:8092/authorization?test=testslice&acr_values=PASSWORD&state=urn%3A"
                       "uuid%3A92d81fb3-72e8-4e6c-9173-c360b782148a&"
                       "redirect_uri=https%3A%2F%2Flocalhost%3A8666%2F919D3F697FDAAF138124B83E09ECB0B7&"
                       "response_type=code&client_id=ok8tx7ulVlNV&scope=openid+profile+email+address+phone")
    assert not body
    assert not ret_kwargs


def test_set_cookie():
    cookiejar = FileCookieJar()
    _cookie = {"value_0": "v_0", "value_1": "v_1", "value_2": "v_2"}
    c = SimpleCookie(_cookie)

    domain_0 = ".test_domain"
    domain_1 = "test_domain"
    max_age = "09 Feb 1994 22:23:32 GMT"
    expires = http2time(max_age)
    path = "test/path"

    c["value_0"]["max-age"] = max_age
    c["value_0"]["domain"] = domain_0
    c["value_0"]["path"] = path

    c["value_1"]["domain"] = domain_1

    util.set_cookie(cookiejar, c)

    cookies = cookiejar._cookies

    c_0 = cookies[domain_0][path]["value_0"]
    c_1 = cookies[domain_1][""]["value_1"]
    c_2 = cookies[""][""]["value_2"]

    assert not (c_2.domain_specified and c_2.path_specified)
    assert c_1.domain_specified and not c_1.domain_initial_dot and not c_1.path_specified
    assert c_0.domain_specified and c_0.domain_initial_dot and c_0.path_specified

    assert c_0.expires == expires
    assert c_0.domain == domain_0
    assert c_0.name == "value_0"
    assert c_0.path == path
    assert c_0.value == "v_0"

    assert not c_1.expires
    assert c_1.domain == domain_1
    assert c_1.name == "value_1"
    assert c_1.path == ""
    assert c_1.value == "v_1"

    assert not c_2.expires
    assert c_2.domain == ""
    assert c_2.name == "value_2"
    assert c_2.path == ""
    assert c_2.value == "v_2"


def test_match_to():
    str0 = "abc"
    str1 = "123"
    str3 = "a1b2c3"

    test_string = "{}{}{}".format(str0, str1, str3)
    assert util.match_to_(str0, test_string)
    assert not util.match_to_(str3, test_string)

    list_of_str = ["test_0", test_string, "test_1", str1]
    assert util.match_to_(str0, list_of_str)
    assert util.match_to_(str1, list_of_str)
    assert not util.match_to_(str3, list_of_str)


def test_verify_header():
    class FakeResponse():
        def __init__(self, header):
            self.headers = {"content-type": header}
            self.text = "TEST_RESPONSE"

    json_header = "application/json"
    jwt_header = "application/jwt"
    default_header = util.DEFAULT_POST_CONTENT_TYPE
    plain_text_header = "text/plain"
    undefined_header = "undefined"

    assert util.verify_header(FakeResponse(json_header), "json") == "json"
    assert util.verify_header(FakeResponse(jwt_header), "json") == "jwt"
    assert util.verify_header(FakeResponse(jwt_header), "jwt") == "jwt"
    assert util.verify_header(FakeResponse(default_header),
                              "urlencoded") == "urlencoded"
    assert util.verify_header(FakeResponse(plain_text_header),
                              "urlencoded") == "urlencoded"

    with pytest.raises(ValueError):
        util.verify_header(FakeResponse(json_header), "urlencoded")
        util.verify_header(FakeResponse(jwt_header), "urlencoded")
        util.verify_header(FakeResponse(default_header), "json")
        util.verify_header(FakeResponse(plain_text_header), "jwt")
        util.verify_header(FakeResponse(undefined_header), "json")
        util.verify_header(FakeResponse(json_header), "undefined")


class TestRenderTemplate(object):

    def test_wrong_template(self):
        with pytest.raises(TemplateException):
            render_template('bogus_template', {'action': 'action'})

    def test_form_post(self):
        response = render_template('form_post', {'action': 'action', 'inputs': {'a': 'a'}})
        assert '<form method="post" action="action">' in response
        assert '<input type="hidden" name="a" value="a"/>' in response

    def test_form_post_missing_inputs(self):
        response = render_template('form_post', {'action': 'action'})
        assert '<form method="post" action="action">' in response

    def test_form_post_missing_action(self):
        with pytest.raises(TemplateException):
            render_template('form_post', {'inputs': {'a': 'a'}})

    def test_verify_logout(self):
        response = render_template('verify_logout', {'action': 'action', 'id_token_hint': 'hint',
                                                     'post_logout_redirect_uri': 'http://example.com'})
        assert 'Please verify logout' in response
        assert '<form method="post" action="action">' in response
        assert '<input type="submit">' in response
        assert '<input type="hidden" name="id_token_hint" value="hint"/>' in response
        assert '<input type="hidden" name="post_logout_redirect_uri" value="http://example.com"/>' in response

    def test_verify_logout_missing_action(self):
        with pytest.raises(TemplateException):
            render_template('verify_logout', {'id_token_hint': 'hint'})

    def test_verify_logout_missing_inputs(self):
        response = render_template('verify_logout', {'action': 'action'})
        assert 'Please verify logout' in response
        assert '<input type="submit">' in response
        assert '<form method="post" action="action">' in response


class TestInputs(object):

    def test_empty(self):
        assert inputs({}) == ''

    def test_single(self):
        assert inputs({'a': 'a'}) == '<input type="hidden" name="a" value="a"/>'

    def test_multiple(self):
        rendered_string = inputs({'a': 'a', 'b': 'b'})

        assert '<input type="hidden" name="a" value="a"/>' in rendered_string
        assert '<input type="hidden" name="b" value="b"/>' in rendered_string
