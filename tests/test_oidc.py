__author__ = 'rohe0002'

from oic import oic
#from oic.oauth2 import MissingRequiredAttribute

from pytest import raises

def _eq(l1, l2):
    return set(l1) == set(l2)

def test_authz_req_urlencoded_1():
    ar = oic.AuthorizationRequest(["code"], "foobar")
    ue = ar.get_urlencoded()
    print ue
    assert ue == "response_type=code&client_id=foobar"

def test_authz_req_urlencoded_2():
    ar = oic.AuthorizationRequest(["code"], "foobar",
                                     "http://foobar.example.com/oaclient",
                                     state="cold")
    ue = ar.get_urlencoded()
    print ue
    assert ue == "state=cold&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar"

def test_authz_req_urlencoded_3():
    ar = oic.AuthorizationRequest(["token"],
                                    "s6BhdRkqt3",
                                    "https://client.example.com/cb",
                                    state="xyz")
    ue = ar.get_urlencoded()
    print ue
    assert ue == "state=xyz&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&response_type=token&client_id=s6BhdRkqt3"

def test_authz_req_urlencoded_4():
    ar = oic.AuthorizationRequest(["code"], "foobar")
    urlencoded = ar.get_urlencoded()
    ar2 = oic.AuthorizationRequest.set_urlencoded(urlencoded)

    print ar
    print ar2
    
    for attr in ar.c_attributes.keys():
        assert getattr(ar, attr) == getattr(ar2, attr)
    
def test_authz_req_urlencoded_5():
    ar = oic.AuthorizationRequest(["code"], "foobar",
                                     "http://foobar.example.com/oaclient",
                                     ["foo", "bar"],
                                     state="cold")

    ue = ar.get_urlencoded()
    print ue
    assert ue == "state=cold&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar&scope=foo+bar"

def test_authz_req_urlencoded_6():
    ar = oic.AuthorizationRequest(["code"], "foobar",
                                     "http://foobar.example.com/oaclient",
                                     ["foo", "bar"],
                                     state="cold")

    urlencoded = ar.get_urlencoded()
    ar2 = oic.AuthorizationRequest.set_urlencoded(urlencoded)

    for attr in ar.c_attributes.keys():
        assert getattr(ar, attr) == getattr(ar2, attr)

#def test_authz_req_urlencoded_7():
#    ar = oic.AuthorizationRequest()
#    raises(MissingRequiredAttribute, ar.verify)

def test_authz_req_urlencoded_8():
    ar = oic.AuthorizationRequest(response_type=[10],
                                    client_id="foobar",
                                    redirect_uri="http://foobar.example.com/oaclient",
                                    scope=["foo", "bar"],
                                    state="cold")

    raises(ValueError, ar.verify)

def test_authz_req_urlencoded_9():
    txt = "scope=foo+bar&state=-11&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar"

    ar = oic.AuthorizationRequest.set_urlencoded(txt)
    print ar
    assert ar.state == "-11"
    

def test_authz_req_json_1():
    ar = oic.AuthorizationRequest(response_type=["code"], client_id="foobar")
    js = ar.get_json()
    print js
    assert js == '{"response_type": ["code"], "client_id": "foobar"}'

def test_authz_req_json_2():
    ar = oic.AuthorizationRequest(response_type=["code"], client_id="foobar",
                            redirect_uri="http://foobar.example.com/oaclient",
                            state="cold")
    ue = ar.get_json()
    print ue
    assert ue == '{"state": "cold", "redirect_uri": "http://foobar.example.com/oaclient", "response_type": ["code"], "client_id": "foobar"}'

def test_authz_req_urlencoded_3():
    ar = oic.AuthorizationRequest(response_type=["token"],
                                    client_id="s6BhdRkqt3",
                                    redirect_uri="https://client.example.com/cb",
                                    state="xyz")
    ue = ar.get_json()
    print ue
    assert ue == '{"state": "xyz", "redirect_uri": "https://client.example.com/cb", "response_type": ["token"], "client_id": "s6BhdRkqt3"}'

def test_authz_req_urlencoded_4():
    ar = oic.AuthorizationRequest(response_type=["code"], client_id="foobar")
    jtxt = ar.get_json()
    ar2 = oic.AuthorizationRequest.set_json(jtxt)

    print ar
    print ar2

    for attr in ar.c_attributes.keys():
        assert getattr(ar, attr) == getattr(ar2, attr)

def test_authz_req_x1():
    query = 'redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauthz&response_type=code&client_id=0123456789'

    ar = oic.AuthorizationRequest.set_urlencoded(query)

    print ar

    assert ar.verify()

# AuthorizationErrorResponse

def test_authz_err_resp_1():
    aer = oic.AuthorizationErrorResponse(error="access_denied", state="xyz")

    assert aer
    print aer.__dict__.items()
    assert aer.error == "access_denied"
    assert aer.state == "xyz"
    assert aer.c_extension == {}

def test_authz_err_resp_2():
    aer = oic.AuthorizationErrorResponse(error="access_denied",
                            error_description="brewers has a four game series",
                            foo="bar")

    assert aer
    print aer.__dict__.items()
    assert aer.error == "access_denied"
    assert aer.error_description == "brewers has a four game series"
    assert aer.c_extension == {'foo': ['bar']}

# TokenErrorResponse

def test_authz_err_resp_1():
    ter = oic.TokenErrorResponse(error="access_denied", state="xyz")

    assert ter
    print ter.__dict__.items()
    assert ter.error == "access_denied"
    assert ter.c_extension == {'state': 'xyz'}

def test_authz_err_resp_2():
    ter = oic.TokenErrorResponse(error="access_denied",
                            error_description="brewers has a four game series",
                            foo="bar")

    assert ter
    print ter.__dict__.items()
    assert ter.error == "access_denied"
    assert ter.error_description == "brewers has a four game series"
    assert ter.c_extension == {'foo': 'bar'}

# AccessTokenResponse

def test_accesstokenreponse_1():
    at = oic.AccessTokenResponse("SlAV32hkKG", "8xLOxBtZp8", 3600)

    assert at
    atj = at.get_json()
    print atj
    assert atj == '{"token_type": "8xLOxBtZp8", "access_token": "SlAV32hkKG", "expires_in": 3600}'

# AccessTokenRequest

def test_extra():
    atr = oic.AccessTokenRequest("authorization_code",
                                    "SplxlOBeZQQYbYS6WxSbIA",
                                    "https://client.example.com/cb",
                                    "abcabc",
                                    extra="foo")

    assert atr
    assert atr.client_id == "abcabc"
    query = atr.get_urlencoded(True)
    print query
    assert query == "code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&client_id=abcabc&grant_type=authorization_code&extra=foo"

    atr2 = oic.AccessTokenRequest.set_urlencoded(query, True)
    print atr2.c_extension
    assert atr2.c_extension == {"extra": "foo"}

# AuthorizationResponse

def test_authz_resp_1():
    atr = oic.AuthorizationResponse("SplxlOBeZQQYbYS6WxSbIA",
                                        "Fun_state",
                                        extra="foo")

    assert atr.code == "SplxlOBeZQQYbYS6WxSbIA"
    assert atr.state == "Fun_state"
    print atr.c_extension
    assert atr.c_extension == {"extra": "foo"}

# RefreshAccessTokenRequest

def test_ratr():
    ratr = oic.RefreshAccessTokenRequest(refresh_token="ababababab")

    assert ratr.grant_type == "refresh_token"
    assert ratr.refresh_token == "ababababab"

    assert ratr.verify()

def test_jwt():
    # CLAIMS don't natively contain any parameters hence everything is
    # based on parameter extensions
    claims = oic.CLAIMS(name=None, nickname={"optional": True},
                 email=None, verified=None,
                 picture={"optional": True})

    uic = oic.UserInfoClaim(claims, format="signed", locale="us-en")

    id_token = oic.IDTokenClaim(max_age=86400, iso29115="2")

    ar = oic.AuthorizationRequest(["code","id_token"], "s6BhdRkqt3",
                            "https://client.example.com/cb",
                            ["openid", "profile"],
                            "af0ifjsldkj")

    oir = oic.OpenIDRequest(ar.response_type, ar.client_id, ar.redirect_uri,
                            ar.scope, ar.state, uic, id_token)

    print oir.get_json(extended=True)
    
    _jwt = oir.get_jwt(key="123456", extended=True)

    print _jwt
    assert _jwt == ("eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.IntcImlkX3Rva2Vu"
                    "XCI6IHtcIm1heF9hZ2VcIjogODY0MDAsIFwiaXNvMjkxMTVcIjogXCIyX"
                    "CJ9LCBcInVzZXJfaW5mb1wiOiB7XCJsb2NhbGVcIjogXCJ1cy1lblwiLC"
                    "BcImNsYWltc1wiOiB7XCJwaWN0dXJlXCI6IHtcIm9wdGlvbmFsXCI6IHR"
                    "ydWV9LCBcIm5pY2tuYW1lXCI6IHtcIm9wdGlvbmFsXCI6IHRydWV9LCBc"
                    "InZlcmlmaWVkXCI6IG51bGwsIFwiZW1haWxcIjogbnVsbCwgXCJuYW1lX"
                    "CI6IG51bGx9LCBcImZvcm1hdFwiOiBcInNpZ25lZFwifSwgXCJzdGF0ZV"
                    "wiOiBcImFmMGlmanNsZGtqXCIsIFwicmVkaXJlY3RfdXJpXCI6IFwiaHR"
                    "0cHM6Ly9jbGllbnQuZXhhbXBsZS5jb20vY2JcIiwgXCJyZXNwb25zZV90"
                    "eXBlXCI6IFtcImNvZGVcIiwgXCJpZF90b2tlblwiXSwgXCJjbGllbnRfa"
                    "WRcIjogXCJzNkJoZFJrcXQzXCIsIFwic2NvcGVcIjogW1wib3BlbmlkXC"
                    "IsIFwicHJvZmlsZVwiXX0i.YhbFe8kxHP4nwzPMbE15eM8lFhQcjJnO_C"
                    "HR-91jfdo")

    or2 = oic.OpenIDRequest.set_jwt(_jwt, key="123456")

    print or2.dictionary()

    assert or2.client_id == "s6BhdRkqt3"
    assert or2.scope == [u'openid', u'profile']
    assert or2.response_type == ["code","id_token"]
    assert or2.redirect_uri == "https://client.example.com/cb"
    assert or2.state == "af0ifjsldkj"
    assert or2.id_token.dictionary() == {u'max_age': 86400, u'iso29115': u'2'}
    assert or2.user_info.dictionary() == {u'claims': {u'picture':
                                                            {u'optional': True},
                                         u'verified': None,
                                         u'nickname': {u'optional': True},
                                         u'name': None,
                                         u'email': None},
                             u'format': u'signed',
                             u'locale': u'us-en'}

    assert oir.client_id == or2.client_id
    assert oir.scope == or2.scope
    assert oir.response_type == or2.response_type
    assert oir.redirect_uri == or2.redirect_uri
    assert oir.state == or2.state
    assert oir.id_token.dictionary(extended=True) == or2.id_token.dictionary(extended=True)
    assert oir.user_info.dictionary(extended=True) == or2.user_info.dictionary(extended=True)

def test_reset():
    claims = oic.CLAIMS(name=None, nickname={"optional": True},
                 email=None, verified=None,
                 picture={"optional": True})

    uic = oic.UserInfoClaim(claims, format="signed")

    id_token = oic.IDTokenClaim(max_age=86400, iso29115="2")

    ar = oic.AuthorizationRequest(["code","id_token"], "s6BhdRkqt3",
                            "https://client.example.com/cb",
                            ["openid", "profile"],
                            "af0ifjsldkj")

    oir = oic.OpenIDRequest(ar.response_type, ar.client_id, ar.redirect_uri,
                            ar.scope, ar.state, uic, id_token)

    oirdic = oir.dictionary()
    print oirdic.keys()
    assert _eq(oirdic.keys(), ['id_token', 'user_info', 'state',
                               'redirect_uri', 'response_type', 'client_id',
                               'scope'])
    assert oirdic["user_info"].keys() == ['claims', 'format']
    assert oirdic["user_info"]["format"] == "signed"
    assert oirdic["id_token"].keys() == ["max_age", "iso29115"]

    odict = oir.dictionary(extended=True)
    oir2 = oic.OpenIDRequest(**odict)

    assert oir2.keys() == oir.keys()

#def test_oid_req():
    client = oic.Client()
    client.redirect_uri = "http://example.com/redirect"
    client.client_id = "1"

    claims = {
        "name":None,
        "email":None,
        "verified":None,
        "nickname": {"optional": True},
        "picture": {"optional": True},
    }

    uinfo_format="signed"
    id_token_restriction = { "max_age": 86400, "iso29115": "2"}

    kwargs = { "response_type": ["code","id_token"],
               "client_id": "s6BhdRkqt3",
               "redirect_uri": "https://client.example.com/cb",
               "scope": ["openid", "profile"],
               "state": "af0ifjsldkj",
    }

    oir = client.get_open_id_request(claims=claims, uinfo_format=uinfo_format,
                                     id_token_restriction=id_token_restriction,
                                     **kwargs)

    oirdic = oir.dictionary(extended=True)
    print oirdic.keys()
    assert _eq(oirdic.keys(), ['id_token', 'user_info', 'state',
                               'redirect_uri', 'response_type', 'client_id',
                               'scope'])

    print oirdic["user_info"]
    assert oirdic["user_info"].keys() == ['claims', 'format']
    assert oirdic["user_info"]["format"] == "signed"
    assert oirdic["id_token"].keys() == ["max_age", "iso29115"]

    srv = oic.Server()
    poir = srv.parse_open_id_request(oir.get_json(extended=True))
    assert _eq(poir.keys(), ['id_token', 'user_info', 'state',
                               'redirect_uri', 'response_type', 'client_id',
                               'scope'])
    assert _eq(poir["user_info"].keys(), ['claims', 'format'])
    assert poir["user_info"]["format"] == "signed"
    assert _eq(poir["id_token"].keys(), ["max_age", "iso29115"])


def test_check_session_request():
    srv = oic.Server({"provider":"098zyx"})

    _jwt = ("eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.IntcImlzc1wiOiBcInByb3ZpZGVyXCIsIFwidXNlcl9pZFwiOiBcImR1bW15XCIsIFwiYXVkXCI6IFwidGVzdENvbnN1bWVyXCIsIFwiZXhwXCI6IDEzMTU5NDY5NTYuNDIwMDU2LCBcImlzbzI5MTE1XCI6IFwiMlwifSI.dfwtaOBXZQG0Xg9Z-Ji3VSc0Br29oMvR3HrTjiX2ft8")

    idt = srv.parse_check_session_request(query="id_token=%s" % _jwt)
    print idt
    assert isinstance(idt, oic.IdToken)

def test_key_object():
    d = {"algorithm":"EC",
          "curve":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "use":"encryption",
          "keyid":"1"}

    keyobj = oic.JWKEllipticKeyObject(**d)

    assert _eq(keyobj.keys(),['use', 'keyid', 'algorithm', 'curve', 'y', 'x'])

def test_key_container():
    jsn = """{"keyvalues":[{"algorithm":"EC","curve":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"encryption","keyid":"1"},{"algorithm":"RSA","modulus": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","exponent":"AQAB","keyid":"2011-04-29"}]}"""

    jco = oic.JWKContainerObject.set_json(jsn)
    assert jco is not None
    assert len(jco.keyvalues) == 2

    jdic = jco.dictionary(extended=True)
    assert jdic.keys() == ["keyvalues"]