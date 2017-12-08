# -*- coding: utf-8 -*-
import pytest

from oic.oauth2.message import AccessTokenRequest
from oic.utils.sanitize import sanitize


@pytest.mark.parametrize("raw,expected", [
    ('code=%5B999%5D&bing=baz&password=foo&param1=bar',
     'code=<REDACTED>&bing=baz&password=<REDACTED>&param1=bar'),

    (AccessTokenRequest(grant_type='authorization_code', redirect_uri=u'http://example.com/authz',
                        client_id='client1', client_secret='hemlighet',
                        code=u'0x+QZlw/S2O9NJKVqB/LDzzhod4v/FVh6ULK/0OnFsfOFRQcux5ow=='),

     {'grant_type': 'authorization_code', 'redirect_uri': u'http://example.com/authz',
      'client_id': 'client1', 'client_secret': '<REDACTED>', 'code': u'<REDACTED>'}),

    (
        ("{'grant_type': 'authorization_code', 'redirect_uri': u'http://example.com/authz', "
         "'client_id': 'client1', 'client_secret': 'hemlighet', "
         "'code': u'0x+QZlw/S2O9NJKVqB/LDzzhod4v/FVh6ULK/0OnFsfOFRQcux5ow=='}"),

        ("{'grant_type': 'authorization_code', 'redirect_uri': u'http://example.com/authz', "
         "'client_id': 'client1', 'client_secret': '<REDACTED>', 'code': u'<REDACTED>'}")
    ),

    ({'Password': 'foo', 'param1': 'bar', 'CODE': [999], 'bing': 'baz'},
     {'bing': 'baz', 'code': '<REDACTED>', 'param1': 'bar', 'password': '<REDACTED>'}),

    ("{'code': [999], 'bing': 'baz', 'password': 'foo', 'param1': 'bar'}",
     "{'code': [<REDACTED>], 'bing': 'baz', 'password': '<REDACTED>', 'param1': 'bar'}"),

    ([('code', [999]), ('bing', 'baz'), ('password', 'foo'), ('param1', 'bar')],
     "[('code', [<REDACTED>]), ('bing', 'baz'), ('password', '<REDACTED>'), ('param1', 'bar')]"),

    ('Password=ubar&param=foo', 'Password=<REDACTED>&param=foo'),
    ({'password': u'bar', 'client_secret': b'foo'}, {'password': '<REDACTED>', 'client_secret': '<REDACTED>'}),
    (u'code=ščřžáíé', 'code=<REDACTED>'),
    ({'code': 'ščřžáíé'}, {'code': '<REDACTED>'}),
])
def test_sanitize(raw, expected):
    assert sanitize(raw) == expected


def test_sanitize_preserves_original():
    old = {'passwd': 'secret'}
    new = sanitize(old)
    assert old['passwd'] == 'secret'
    assert new['passwd'] == '<REDACTED>'
