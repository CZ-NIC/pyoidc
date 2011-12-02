__author__ = 'rohe0002'

from oic.oic import *

from pytest import raises

def _eq(l1, l2):
    return set(l1) == set(l2)

def test_to_fro_json():
    _dict = {"this":"kate"}

    jso = to_json(_dict)

    _dic = from_json(jso)

    assert _dict.keys() == _dic.keys()
    assert _dict == _dic

def test_claims_deser_ser():
    claim = CLAIMS(name=None, nickname={"optional": True},
                 email=None, verified=None,
                 picture={"optional": True})

    items = claims_ser([claim])

    claims = claims_deser(items)

    assert claim.c_extension == claims[0].c_extension

    items = claims_ser([claim], format="json")

    claims = claims_deser(items, format="json")

    assert claim.c_extension == claims[0].c_extension

    items = claims_ser([claim], format="dict")

    claims = claims_deser(items, format="dict")

    assert claim.c_extension == claims[0].c_extension

def test_authz_req():
    ar = AuthorizationRequest(["code","id_token"], "s6BhdRkqt3",
                            "https://client.example.com/cb",
                            ["openid", "profile"],
                            "af0ifjsldkj", display="popup", prompt=["login"])

    assert ar.verify()

def test_authz_req_urlencoded_1():
    ar = AuthorizationRequest(["code"], "foobar")
    ue = ar.get_urlencoded()
    print ue
    assert ue == "response_type=code&client_id=foobar"

def test_authz_req_urlencoded_2():
    ar = AuthorizationRequest(["code"], "foobar",
                                     "http://foobar.example.com/oaclient",
                                     state="cold")
    ue = ar.get_urlencoded()
    print ue
    assert ue == "state=cold&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar"

def test_authz_req_urlencoded_3():
    ar = AuthorizationRequest(["token"],
                                    "s6BhdRkqt3",
                                    "https://client.example.com/cb",
                                    state="xyz")
    ue = ar.get_urlencoded()
    print ue
    assert ue == "state=xyz&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&response_type=token&client_id=s6BhdRkqt3"

def test_authz_req_urlencoded_4():
    ar = AuthorizationRequest(["code"], "foobar")
    urlencoded = ar.get_urlencoded()
    ar2 = AuthorizationRequest.set_urlencoded(urlencoded)

    print ar
    print ar2
    
    for attr in ar.c_attributes.keys():
        assert getattr(ar, attr) == getattr(ar2, attr)
    
def test_authz_req_urlencoded_5():
    ar = AuthorizationRequest(["code"], "foobar",
                                     "http://foobar.example.com/oaclient",
                                     ["foo", "bar"],
                                     state="cold")

    ue = ar.get_urlencoded()
    print ue
    assert ue == "state=cold&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar&scope=foo+bar"

def test_authz_req_urlencoded_6():
    ar = AuthorizationRequest(["code"], "foobar",
                                     "http://foobar.example.com/oaclient",
                                     ["foo", "bar"],
                                     state="cold")

    urlencoded = ar.get_urlencoded()
    ar2 = AuthorizationRequest.set_urlencoded(urlencoded)

    for attr in ar.c_attributes.keys():
        assert getattr(ar, attr) == getattr(ar2, attr)

#def test_authz_req_urlencoded_7():
#    ar = AuthorizationRequest()
#    raises(MissingRequiredAttribute, ar.verify)

def test_authz_req_urlencoded_8():
    ar = AuthorizationRequest(response_type=[10],
                                    client_id="foobar",
                                    redirect_uri="http://foobar.example.com/oaclient",
                                    scope=["foo", "bar"],
                                    state="cold")

    raises(ValueError, ar.verify)

def test_authz_req_urlencoded_9():
    txt = "scope=foo+bar&state=-11&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar"

    ar = AuthorizationRequest.set_urlencoded(txt)
    print ar
    assert ar.state == "-11"
    

def test_authz_req_json_1():
    ar = AuthorizationRequest(response_type=["code"], client_id="foobar")
    js = ar.get_json()
    print js
    assert js == '{"response_type": ["code"], "client_id": "foobar"}'

def test_authz_req_json_2():
    ar = AuthorizationRequest(response_type=["code"], client_id="foobar",
                            redirect_uri="http://foobar.example.com/oaclient",
                            state="cold")
    ue = ar.get_json()
    print ue
    assert ue == '{"state": "cold", "redirect_uri": "http://foobar.example.com/oaclient", "response_type": ["code"], "client_id": "foobar"}'

def test_authz_req_urlencoded_3():
    ar = AuthorizationRequest(response_type=["token"],
                                    client_id="s6BhdRkqt3",
                                    redirect_uri="https://client.example.com/cb",
                                    state="xyz")
    ue = ar.get_json()
    print ue
    assert ue == '{"state": "xyz", "redirect_uri": "https://client.example.com/cb", "response_type": ["token"], "client_id": "s6BhdRkqt3"}'

def test_authz_req_urlencoded_4():
    ar = AuthorizationRequest(response_type=["code"], client_id="foobar")
    jtxt = ar.get_json()
    ar2 = AuthorizationRequest.set_json(jtxt)

    print ar
    print ar2

    for attr in ar.c_attributes.keys():
        assert getattr(ar, attr) == getattr(ar2, attr)

def test_authz_req_x1():
    query = 'redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauthz&response_type=code&client_id=0123456789'

    ar = AuthorizationRequest.set_urlencoded(query)

    print ar

    assert ar.verify()

# AuthorizationErrorResponse

def test_authz_err_resp_1():
    aer = AuthorizationErrorResponse(error="access_denied", state="xyz")

    assert aer
    assert aer.verify()
    print aer.__dict__.items()
    assert aer.error == "access_denied"
    assert aer.state == "xyz"
    assert aer.c_extension == {}

#noinspection PyUnusedLocal
def test_authz_err_resp_2():
    aer = AuthorizationErrorResponse(error="user_mismatched",
                            error_description="brewers has a four game series",
                            foo="bar")

    assert aer
    print aer.__dict__.items()
    assert aer.error == "user_mismatched"
    assert aer.error_description == "brewers has a four game series"
    assert aer.c_extension == {'foo': 'bar'}

    aer = AuthorizationErrorResponse(error="access_fooed",
                            error_description="brewers has a four game series",
                            foo="bar")

    raises(Exception, "aer.verify()")

# TokenErrorResponse

def test_token_err_resp_1():
    ter = TokenErrorResponse(error="invalid_authorization_code", state="xyz")

    assert ter
    assert ter.verify()
    print ter.__dict__.items()
    assert ter.error == "invalid_authorization_code"
    assert ter.c_extension == {'state': 'xyz'}

def test_token_err_resp_2():
    ter = TokenErrorResponse(error="invalid_client",
                            error_description="brewers has a four game series",
                            foo="bar")

    assert ter
    assert ter.verify()
    print ter.__dict__.items()
    assert ter.error == "invalid_client"
    assert ter.error_description == "brewers has a four game series"
    assert ter.c_extension == {'foo': 'bar'}

# AccessTokenResponse

def test_accesstokenreponse_1():
    at = AccessTokenResponse("SlAV32hkKG", "8xLOxBtZp8", 3600)

    assert at
    atj = at.get_json()
    print atj
    assert atj == '{"token_type": "8xLOxBtZp8", "access_token": "SlAV32hkKG", "expires_in": 3600}'

# AccessTokenRequest

def test_extra():
    atr = AccessTokenRequest("authorization_code",
                                    "SplxlOBeZQQYbYS6WxSbIA",
                                    "https://client.example.com/cb",
                                    "abcabc",
                                    extra="foo")

    assert atr
    assert atr.client_id == "abcabc"
    query = atr.get_urlencoded(True)
    print query
    assert query == "code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&client_id=abcabc&grant_type=authorization_code&extra=foo"

    atr2 = AccessTokenRequest.set_urlencoded(query, True)
    print atr2.c_extension
    assert atr2.c_extension == {"extra": "foo"}

# AuthorizationResponse

def test_authz_resp_1():
    atr = AuthorizationResponse("SplxlOBeZQQYbYS6WxSbIA",
                                        "Fun_state",
                                        extra="foo")

    assert atr.code == "SplxlOBeZQQYbYS6WxSbIA"
    assert atr.state == "Fun_state"
    print atr.c_extension
    assert atr.c_extension == {"extra": "foo"}

# RefreshAccessTokenRequest

def test_ratr():
    ratr = RefreshAccessTokenRequest(refresh_token="ababababab",
                                         client_id="1")

    assert ratr.grant_type == "refresh_token"
    assert ratr.refresh_token == "ababababab"
    assert ratr.client_id == "1"

    assert ratr.verify()

def test_jwt():
    # CLAIMS don't natively contain any parameters hence everything is
    # based on parameter extensions
    claims = CLAIMS(name=None, nickname={"optional": True},
                 email=None, verified=None,
                 picture={"optional": True})

    uic = UserInfoClaim([claims], format="signed", locale="us-en")

    id_token = IDTokenClaim(max_age=86400, iso29115="2")

    ar = AuthorizationRequest(["code","id_token"], "s6BhdRkqt3",
                            "https://client.example.com/cb",
                            ["openid", "profile"],
                            "af0ifjsldkj")

    oir = OpenIDRequest(ar.response_type, ar.client_id, ar.redirect_uri,
                            ar.scope, ar.state, uic, id_token)

    print oir.get_json(extended=True)
    
    _jwt = oir.get_jwt(key="123456", extended=True)

    print _jwt
    assert _jwt == "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.IntcImlkX3Rva2VuXCI6IHtcIm1heF9hZ2VcIjogODY0MDAsIFwiaXNvMjkxMTVcIjogXCIyXCJ9LCBcInVzZXJfaW5mb1wiOiB7XCJsb2NhbGVcIjogXCJ1cy1lblwiLCBcImNsYWltc1wiOiBbe1wicGljdHVyZVwiOiB7XCJvcHRpb25hbFwiOiB0cnVlfSwgXCJ2ZXJpZmllZFwiOiBudWxsLCBcIm5pY2tuYW1lXCI6IHtcIm9wdGlvbmFsXCI6IHRydWV9LCBcImVtYWlsXCI6IG51bGwsIFwibmFtZVwiOiBudWxsfV0sIFwiZm9ybWF0XCI6IFwic2lnbmVkXCJ9LCBcInN0YXRlXCI6IFwiYWYwaWZqc2xka2pcIiwgXCJyZWRpcmVjdF91cmlcIjogXCJodHRwczovL2NsaWVudC5leGFtcGxlLmNvbS9jYlwiLCBcInJlc3BvbnNlX3R5cGVcIjogW1wiY29kZVwiLCBcImlkX3Rva2VuXCJdLCBcImNsaWVudF9pZFwiOiBcInM2QmhkUmtxdDNcIiwgXCJzY29wZVwiOiBbXCJvcGVuaWRcIiwgXCJwcm9maWxlXCJdfSI.qr9KVGhR1O09twGJtmiF-TXuunD2oiCv2CFQi9lCPQQ"

    or2 = OpenIDRequest.set_jwt(_jwt, key="123456")

    print or2.dictionary()

    assert or2.client_id == "s6BhdRkqt3"
    assert or2.scope == [u'openid', u'profile']
    assert or2.response_type == ["code","id_token"]
    assert or2.redirect_uri == "https://client.example.com/cb"
    assert or2.state == "af0ifjsldkj"
    assert or2.id_token.dictionary() == {u'max_age': 86400, u'iso29115': u'2'}
    print or2.user_info.dictionary()
    assert or2.user_info.dictionary() == {
        'locale': u'us-en',
        'claims': [{u'picture': {u'optional': True},
                    u'nickname': {u'optional': True},
                    u'verified': None,
                    u'email': None,
                    u'name': None}],
        'format': u'signed'}

    assert oir.client_id == or2.client_id
    assert oir.scope == or2.scope
    assert oir.response_type == or2.response_type
    assert oir.redirect_uri == or2.redirect_uri
    assert oir.state == or2.state
    assert oir.id_token.dictionary(extended=True) == or2.id_token.dictionary(extended=True)
    assert oir.user_info.dictionary(extended=True) == or2.user_info.dictionary(extended=True)

def test_reset():
    claims = CLAIMS(name=None, nickname={"optional": True},
                 email=None, verified=None,
                 picture={"optional": True})

    uic = UserInfoClaim([claims], format="signed")

    id_token = IDTokenClaim(max_age=86400, iso29115="2")

    ar = AuthorizationRequest(["code","id_token"], "s6BhdRkqt3",
                            "https://client.example.com/cb",
                            ["openid", "profile"],
                            "af0ifjsldkj")

    oir = OpenIDRequest(ar.response_type, ar.client_id, ar.redirect_uri,
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
    oir2 = OpenIDRequest(**odict)

    assert oir2.keys() == oir.keys()

#def test_oid_req():
#    client = Client()
#    client.redirect_uri = "http://example.com/redirect"
#    client.client_id = "1"
#
#    claims = {
#        "name":None,
#        "email":None,
#        "verified":None,
#        "nickname": {"optional": True},
#        "picture": {"optional": True},
#    }
#
#    uinfo_format="signed"
#    id_token_restriction = { "max_age": 86400, "iso29115": "2"}
#
#    kwargs = { "response_type": ["code","id_token"],
#               "client_id": "s6BhdRkqt3",
#               "redirect_uri": "https://client.example.com/cb",
#               "scope": ["openid", "profile"],
#               "state": "af0ifjsldkj",
#    }
#
#    oir = client.get_open_id_request(claims=claims, uinfo_format=uinfo_format,
#                                     id_token_restriction=id_token_restriction,
#                                     **kwargs)
#
#    oirdic = oir.dictionary(extended=True)
#    print oirdic.keys()
#    assert _eq(oirdic.keys(), ['id_token', 'user_info', 'state',
#                               'redirect_uri', 'response_type', 'client_id',
#                               'scope'])
#
#    print oirdic["user_info"]
#    assert oirdic["user_info"].keys() == ['claims', 'format']
#    assert oirdic["user_info"]["format"] == "signed"
#    assert oirdic["id_token"].keys() == ["max_age", "iso29115"]
#
#    srv = Server()
#    poir = srv.parse_open_id_request(oir.get_json(extended=True))
#    assert _eq(poir.keys(), ['id_token', 'user_info', 'state',
#                               'redirect_uri', 'response_type', 'client_id',
#                               'scope'])
#    assert _eq(poir["user_info"].keys(), ['claims', 'format'])
#    assert poir["user_info"]["format"] == "signed"
#    assert _eq(poir["id_token"].keys(), ["max_age", "iso29115"])
#
#
#def test_check_session_request():
#    srv = Server({"provider":"098zyx"})
#
#    _jwt = ("eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.IntcImlzc1wiOiBcInByb3ZpZGVyXCIsIFwidXNlcl9pZFwiOiBcImR1bW15XCIsIFwiYXVkXCI6IFwidGVzdENvbnN1bWVyXCIsIFwiZXhwXCI6IDEzMTU5NDY5NTYuNDIwMDU2LCBcImlzbzI5MTE1XCI6IFwiMlwifSI.dfwtaOBXZQG0Xg9Z-Ji3VSc0Br29oMvR3HrTjiX2ft8")
#
#    idt = srv.parse_check_session_request(query="id_token=%s" % _jwt)
#    print idt
#    assert isinstance(idt, IdToken)

def test_key_object():
    d = {"algorithm":"EC",
          "curve":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "use":"encryption",
          "keyid":"1"}

    keyobj = JWKEllipticKeyObject(**d)

    assert _eq(keyobj.keys(),['use', 'keyid', 'algorithm', 'curve', 'y', 'x'])

def test_key_container():
    jsn = """{"keyvalues":[{"algorithm":"EC","curve":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM","use":"encryption","keyid":"1"},{"algorithm":"RSA","modulus": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","exponent":"AQAB","keyid":"2011-04-29"}]}"""

    jco = JWKContainerObject.set_json(jsn)
    assert jco is not None
    assert len(jco.keyvalues) == 2

    jdic = jco.dictionary(extended=True)
    assert jdic.keys() == ["keyvalues"]

def test_auth_response_code():
    aresp = AuthorizationResponse(
        code="Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk",
        state="af0ifjsldkj")

    assert aresp.dictionary() == {
        "code": "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk",
        "state": "af0ifjsldkj"}

def test_auth_response_token():
    aresp = AuthorizationResponse(
        access_token="jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y",
        token_type="Bearer",
        state="af0ifjsldkj")

    assert aresp.dictionary() == {
        "access_token": "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y",
        "token_type": "Bearer",
        "state": "af0ifjsldkj"}

def test_auth_response_code_and_token():
    aresp = AuthorizationResponse(
        code="Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk",
        access_token="jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y",
        token_type="Bearer",
        state="af0ifjsldkj")

    assert aresp.dictionary() == {
        "code": "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk",
        "access_token": "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y",
        "token_type": "Bearer",
        "state": "af0ifjsldkj"}

def test_auth_response_code_and_token():
    aresp = AuthorizationResponse(
        code="Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk",
        access_token="jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y",
        token_type="Bearer",
        id_token="eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ.foo",
        state="af0ifjsldkj")

    assert aresp.dictionary() == {
        "code": "Qcb0Orv1zh30vL1MPRsbm-diHiMwcLyZvn1arpZv-Jxf_11jnpEX3Tgfvk",
        "access_token": "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y",
        "token_type": "Bearer",
        "id_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ.foo",
        "state": "af0ifjsldkj"}

#def test_X():
#    from oic.oic.consumer import Client
#
#    resp = "nonce=uqfc3MhAVhMn&code=gMepFsHWQ%2BaUR89FiiAwbx%2BsZM%2FxC%2B%2BhkC66bnqUaJI%3D&access_token=gMepFsHWQ%2BaUR89FiiAwb9Fkmn9B0bS5xkBS651dakQ%3D&expires_in=3600&token_type=bearer&state=eafa67e294f92d3f495ca31931f3e9b3&scope=openid"
#
#    c = Client()
#    aresp = c.parse_authorization_response(query=resp)
#
#    assert aresp.nonce == "uqfc3MhAVhMn"
#    assert aresp.token_type == "bearer"
#    assert aresp.state == "eafa67e294f92d3f495ca31931f3e9b3"
#    assert aresp.scope == ["openid"]

def test_act_1():
    resp = "token_type=bearer&state=9afe48e30d390d6ab163f1f857f576d8&access_token=7kFAO9Gwq59EmaoldboyhhLDnzXgc%2BnP4Gewl50k2Rc%3D&scope=openid&expires_in=3600&refresh_token=7kFAO9Gwq59Emaoldboyhn3aQdsI6czLVRL1k455ZHg%3D"

    atr = AccessTokenResponse().from_urlencoded(resp)

    rdict = {"access_token": "7kFAO9Gwq59EmaoldboyhhLDnzXgc+nP4Gewl50k2Rc=",
             "expires_in": 3600,
             "token_type": "bearer",
             "state": "9afe48e30d390d6ab163f1f857f576d8",
             "scope": ["openid"],
             "refresh_token": "7kFAO9Gwq59Emaoldboyhn3aQdsI6czLVRL1k455ZHg="}

    print atr.to_json()
    assert atr.to_json() == json.dumps(rdict)

def test_user_info_request():
    uir = UserInfoRequest("1234567890", "openid", "identifier")

    assert uir.verify()

def test_user_info_response():
    uir = UserInfoResponse(id="abcdef", name="Derek Jeter",
                           given_name="Derek", family_name="Jeter",
                           phone_number="+1 555 123456")

    assert uir.verify()

def test_provider_configuration_response():
    args = {
        "authorization_endpoint": "https://example.com/connect/authorize",
        "issuer" : "https://example.com",
        "token_endpoint": "https://example.com/connect/token",
        "user_info_endpoint": "https://example.com/connect/user",
        "check_id_endpoint": "https://example.com/connect/check_id",
        "refresh_session_endpoint": "https://example.com/connect/refresh_session",
        "end_session_endpoint": "https://example.com/connect/end_session",
        "jwk_document": "https://example.com/jwk.json",
        "registration_endpoint": "https://example.com/connect/register",
        "scopes_supported": ["openid"],
        "flows_supported": ["code", "token"],
        "iso29115_supported": ["http://www.idmanagement.gov/schema/2009/05/icam/openid-trust-level1.pdf"],
        "identifiers_supported": ["public", "ppid"]
    }
    
    pcr = ProviderConfigurationResponse(**args)

    assert pcr.verify()

def test_registration_request():
    args = {"type":"client_associate",
            "redirect_uri": ["https://client.example.com/callback",
                             "https://client.example.com/callback2"],
            "logo_url":"https://client.example.com/logo.png",
            "application_type": "web"}

    rr = RegistrationRequest(**args)
    assert rr.verify()

def test_registration_response():
    args = {"client_id":"SlAV32hkKG",
            "client_secret":"cf136dc3c1fd9153029bb9c6cc9",
            "expires_in":3600}
    
    rr = RegistrationResponse(**args)

    assert rr.verify()

def test_refresh_session_request():
    args = {
        "id_token": "abcdefghijkl",
        "redirect_url": "http://example.com/session",
        "state": "original"
    }
    rsr = RefreshSessionRequest(**args)

    rsr.verify()

def test_refresh_session_response():
    args = {
        "id_token": "01234567890",
        "state": "original"
    }
    rsr = RefreshSessionResponse(**args)

    rsr.verify()

def test_check_session_request():
    args = {
        "id_token": "01234567890",
    }
    rsr = CheckSessionRequest(**args)

    rsr.verify()

def test_check_id_request():
    args = {
        "id_token": "01234567890",
    }
    rsr = CheckIDRequest(**args)

    rsr.verify()

def test_end_session_request():
    args = {
        "id_token": "abcdefghijkl",
        "redirect_url": "http://example.com/session",
        "state": "original"
    }
    esr = EndSessionRequest(**args)

    esr.verify()

def test_end_session_response():
    esr = EndSessionResponse("state")
    assert esr.verify()

def test_id_token():
    args = {
        "iss": "http://server.example.com",
        "client_id":"http://client.example.com",
        "aud": "http://client.example.com",
        "user_id": "user_328723",
        "exp":"1303852880",
    }

    idt = IdToken(**args)

    idt.verify()

def test_ser_deser_claims():
    claims = CLAIMS(name=None, nickname={"optional": True},
                 email=None, verified=None,
                 picture={"optional": True})

    scl = claims_ser([claims])
    assert len(scl) == 1

    clas = claims_deser(scl)

    assert len(clas) == 1
    cla = clas[0]

    assert _eq(cla.keys(), ['picture', 'verified', 'nickname', 'email', 'name'])

def test_user_info_claim():
    claim = CLAIMS(name=None, nickname={"optional": True},
                 email=None, verified=None,
                 picture={"optional": True})

    uic = UserInfoClaim([claim], format="signed", locale="en")
    assert uic.verify()

def test_jwk_key_object():
    jko = JWKKeyObject("RSA", "signature")
    assert jko.verify()
    
def test_ser_deser_key_object_list():
    jko = [JWKKeyObject("RSA", "signature"), JWKKeyObject("RSA", "encryption")]

    # default == json
    items = key_object_list_serializer(jko)
    assert len(items) == 2
    jkos = key_object_list_deserializer(items)
    assert len(jkos) == 2

    assert isinstance(jkos[0], JWKKeyObject)
    assert isinstance(jkos[1], JWKKeyObject)

    assert jkos[0].algorithm == "RSA"
    assert jkos[0].use == "signature"

    # urlencoded
    items = key_object_list_serializer(jko, format="urlencoded")
    assert len(items) == 2
    jkos = key_object_list_deserializer(items, format="urlencoded")
    assert len(jkos) == 2

    assert isinstance(jkos[0], JWKKeyObject)
    assert isinstance(jkos[1], JWKKeyObject)

    assert jkos[0].algorithm == "RSA"
    assert jkos[0].use == "signature"

#def test_client_parse_access_token_response():
#    client = Client()
#
#    resp = AccessTokenResponse("SlAV32hkKG", "token_type", 3600)
#
#    client.parse_access_token_response(info=resp.get_json(), scope="openid")
#    grant = client.grant["openid"]
#
#    assert grant.access_token == "SlAV32hkKG"
#    assert grant.token_type == "token_type"

#def test_do_authorization_request():
#    client = Client()
#    client.authorization_endpoint = "https://example.com/authz"
#    args = {
#        "response_type":["code"],
#        "client_id":"foobar",
#        "redirect_uri":"http://foobar.example.com/oaclient",
#        "state":"cold",
#    }
#
#    path, h_args = client._do_authorization_request(**args)
#
#    assert h_args == {}
#    print path
#    assert path == "https://example.com/authz?state=cold&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar"
#
#    path, h_args = client._do_authorization_request(
#                                        oic_method="request_parameter", **args)
#
#    assert h_args == {}
#    print path
#    part = urlparse.urlparse(path)
#    print part.query
#
#    arq = AuthorizationRequest.set_urlencoded(part.query)
#    assert _eq(arq.keys(), ['request', 'state', 'response_type', 'client_id',
#                            'redirect_uri'])
#
#    path, h_args = client._do_authorization_request(
#                                        oic_method="request_file", **args)
#
#    assert h_args == {}
#    print path
#    part = urlparse.urlparse(path)
#    print part.query
#
#    arq = AuthorizationRequest.set_urlencoded(part.query)
#    assert _eq(arq.keys(), ['request_uri', 'state', 'response_type', 'client_id',
#                            'redirect_uri'])
#
#def test_client_get_or_post():
#    client = Client()
#    args = {
#        "response_type":["code"],
#        "client_id":"foobar",
#        "redirect_uri":"http://foobar.example.com/oaclient",
#        "state":"cold",
#    }
#    arq = AuthorizationRequest(**args)
#
#    post, kwargs = client.get_or_post("https://example.com/authz", "POST",
#                                      arq)
#
#    print post
#    print kwargs
#
#    assert post == "https://example.com/authz"
#    assert _eq(kwargs.keys(), ['body', 'headers'])
#    assert kwargs["headers"] == {'content-type':
#                                     'application/x-www-form-urlencoded'}
#
#def test_user_info_request():
#    client = Client()
#    client.user_info_endpoint = "https://example.com/userinfo"
#    resp = AccessTokenResponse("SlAV32hkKG", "token_type", 3600)
#
#    client.parse_access_token_response(info=resp.get_json(), scope="openid")
#
#    path, method, h_args = client.user_info_request()
#
#    assert method == "GET"
#    assert h_args == {}
#    assert path == "https://example.com/userinfo?access_token=SlAV32hkKG"
#
#def test_server_parse_urlencoded():
#    srv = Server()
#
#    res = srv._parse_urlencoded("https://example.com/userinfo?access_token=SlAV32hkKG")
#    assert res.keys() == ["access_token"]
#    assert res["access_token"] == ["SlAV32hkKG"]
#
#    res = srv._parse_urlencoded(query="access_token=SlAV32hkKG")
#    assert res.keys() == ["access_token"]
#    assert res["access_token"] == ["SlAV32hkKG"]
#
#def test_server_parse_check_session_request():
#    srv = Server()
#
#    args = {
#        "iss": "http://server.example.com",
#        "aud": "http://client.example.com",
#        "user_id": "user_328723",
#        "exp":"1303852880",
#    }
#
#    srv.jwt_keys[args["iss"]] = "12345678"
#
#    idt = IdToken(**args)
#
#    rsr = CheckSessionRequest(idt.get_jwt(key="12345678"))
#
#    sidt = srv.parse_check_session_request(query=rsr.get_urlencoded())
#
#    assert isinstance(sidt, IdToken)
#
#    assert _eq(sidt.keys(), ['user_id', 'aud', 'iss', 'exp'])
#    assert sidt.dictionary() == args
#
#
#def test_parse_open_id_request():
#    srv = Server()
#
#    ar = AuthorizationRequest(["code","id_token"], "s6BhdRkqt3",
#                            "https://client.example.com/cb",
#                            ["openid", "profile"],
#                            "af0ifjsldkj")
#
#    id_token = IDTokenClaim(max_age=86400, iso29115="2")
#    claims = CLAIMS(name=None, nickname={"optional": True},
#                 email=None, verified=None,
#                 picture={"optional": True})
#
#    uic = UserInfoClaim([claims], format="signed", locale="us-en")
#
#    oir = OpenIDRequest(ar.response_type, ar.client_id, ar.redirect_uri,
#                            ar.scope, ar.state, uic, id_token)
#
#    oidr = srv.parse_open_id_request(oir.get_json())
#
#    print oidr.dictionary()
#
#    assert oidr.dictionary() == {
#        'id_token': {'max_age': 86400, 'iso29115': u'2'},
#        'user_info': {'locale': u'us-en',
#                      'claims': [{u'picture': {u'optional': True},
#                                  u'nickname': {u'optional': True},
#                                  u'verified': None,
#                                  u'email': None,
#                                  u'name': None}],
#                      'format': u'signed'},
#        'state': u'af0ifjsldkj',
#        'redirect_uri': u'https://client.example.com/cb',
#        'response_type': [u'code', u'id_token'],
#        'client_id': u's6BhdRkqt3',
#        'scope': [u'openid', u'profile']}
#
#    oir2 = srv.parse_open_id_request(oir.get_urlencoded(), format="urlencoded")
#
#    print oir2.dictionary()
#
#    assert oir2.dictionary() == {
#            'id_token': {'max_age': 86400, 'iso29115': '2'},
#            'user_info': {'locale': 'us-en',
#                          "claims": [{
#                              'picture': {'optional': True},
#                              'nickname': {'optional': True},
#                              'verified': None,
#                              'email': None,
#                              'name': None}],
#                          'format': 'signed'},
#            'state': 'af0ifjsldkj',
#            'redirect_uri': 'https://client.example.com/cb',
#            'response_type': ['code', 'id_token'],
#            'client_id': 's6BhdRkqt3',
#            'scope': ['openid', 'profile']}
