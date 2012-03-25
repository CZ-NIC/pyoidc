
__author__ = 'rohe0002'

from oic.oauth2.message import *

from pytest import raises

CLASS_SPEC = {
    "param": {
        "req_str": SINGLE_REQUIRED_STRING,
        "opt_str": SINGLE_OPTIONAL_STRING,
        "opt_int": SINGLE_OPTIONAL_INT,
        "opt_str_list": OPTIONAL_LIST_OF_STRINGS,
        "req_str_list": REQUIRED_LIST_OF_STRINGS,
        "opt_json": SINGLE_OPTIONAL_JSON},
}

def _eq(l1, l2):
    return set(l1) == set(l2)

def test_authz_req_urlencoded_1():
    ar = message("AuthorizationRequest", response_type=["code"],
                 client_id = "foobar")
    ue = ar.to_urlencoded()
    print ue
    assert ue == "response_type=code&client_id=foobar"

def test_authz_req_urlencoded_2():
    ar = message("AuthorizationRequest", response_type=["code"],
                 client_id = "foobar",
                 redirect_uri = "http://foobar.example.com/oaclient",
                 state="cold")

    ue = ar.to_urlencoded()
    print ue
    assert ue == "state=cold&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar"

def test_authz_req_urlencoded_3():
    ar = message("AuthorizationRequest", response_type=["token"],
                 client_id="s6BhdRkqt3",
                 redirect_uri="https://client.example.com/cb", state="xyz")

    ue = ar.to_urlencoded()
    print ue
    assert ue == "state=xyz&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&response_type=token&client_id=s6BhdRkqt3"

def test_authz_req_urlencoded_4():
    ar = message("AuthorizationRequest", response_type=["code"],
                 client_id="foobar")

    urlencoded = ar.to_urlencoded()
    ar2 = msg_deser(urlencoded, "urlencoded", typ="AuthorizationRequest")

    print ar
    print ar2

    for attr in ar.c_attributes.keys():
        assert getattr(ar, attr) == getattr(ar2, attr)

def test_authz_req_urlencoded_5():
    ar = message("AuthorizationRequest", response_type = ["code"],
                 client_id="foobar",
                 redirect_uri="http://foobar.example.com/oaclient",
                 scope = ["foo", "bar"], state="cold")

    ue = ar.to_urlencoded()
    print ue
    assert ue == "scope=foo+bar&state=cold&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar"

def test_authz_req_urlencoded_6():
    ar = message("AuthorizationRequest", response_type=["code"],
                 client_id="foobar",
                 redirect_uri="http://foobar.example.com/oaclient",
                 scope=["foo", "bar"], state="cold")

    urlencoded = ar.to_urlencoded()
    ar2 = msg_deser(urlencoded, "urlencoded", typ="AuthorizationRequest")

    assert ar == ar2

def test_authz_req_urlencoded_7():
    ar = message("AuthorizationRequest", response_type=["code"])
    raises(MissingRequiredAttribute, ar.verify)

def test_authz_req_urlencoded_8():
    args = {"response_type":[10], "client_id":"foobar",
            "redirect_uri":"http://foobar.example.com/oaclient",
            "scope":["foo", "bar"], "state":"cold"}

    raises(Exception, 'message("AuthorizationRequest", **args)')

def test_authz_req_urlencoded_9():
    txt = "scope=foo+bar&state=-11&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar"

    ar = msg_deser(txt, "urlencoded", typ="AuthorizationRequest")
    print ar
    assert ar["state"] == "-11"

def test_authz_req_urlencoded_10():
    txt = "scope=openid&state=id-6a3fc96caa7fd5cb1c7d00ed66937134&redirect_uri=http%3A%2F%2Flocalhost%3A8087authz&response_type=code&client_id=a1b2c3"

    ar = msg_deser(txt, "urlencoded", typ="AuthorizationRequest")
    print ar
    assert ar["scope"] == ["openid"]
    assert ar["response_type"] == ["code"]


def test_authz_req_json_1():
    ar = message("AuthorizationRequest", response_type=["code"],
                 client_id="foobar")
    
    js = ar.serialize(method="json")
    print js
    assert js == '{"response_type": ["code"], "client_id": "foobar"}'

def test_authz_req_json_2():
    ar = message("AuthorizationRequest", response_type=["code"], 
                 client_id="foobar",
                 redirect_uri="http://foobar.example.com/oaclient", state="cold")
    
    ue = ar.serialize(method="json")
    print ue
    assert ue == '{"state": "cold", "redirect_uri": "http://foobar.example.com/oaclient", "response_type": ["code"], "client_id": "foobar"}'

def test_authz_req_urlencoded_3():
    ar = message("AuthorizationRequest", response_type=["token"], 
                 client_id="s6BhdRkqt3",
                 redirect_uri="https://client.example.com/cb", state="xyz")
    
    ue = ar.serialize(method="json")
    print ue
    assert ue == '{"state": "xyz", "redirect_uri": "https://client.example.com/cb", "response_type": ["token"], "client_id": "s6BhdRkqt3"}'

def test_authz_req_urlencoded_4():
    ar = message("AuthorizationRequest", response_type=["code"], 
                 client_id="foobar")
    
    jtxt = ar.serialize(method="json")

    ar2 = msg_deser(jtxt, "json", typ="AuthorizationRequest")

    print ar
    print ar2

    assert ar == ar2

def test_authz_req_x1():
    query = 'redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauthz&response_type=code&client_id=0123456789'

    ar = msg_deser(query, format="urlencoded", typ="AuthorizationRequest")

    print ar

    assert ar.verify()

# AuthorizationErrorResponse

def test_authz_err_resp_1():
    aer = message("AuthorizationErrorResponse", error="access_denied", 
                  state="xyz")

    assert aer
    print aer.__dict__.items()
    assert aer["error"] == "access_denied"
    assert aer["state"] == "xyz"

def test_authz_err_resp_2():
    aer = message("AuthorizationErrorResponse", error="access_denied",
                  error_description="brewers has a four game series", 
                  foo="bar")

    assert aer
    print aer.__dict__.items()
    assert aer["error"] == "access_denied"
    assert aer["error_description"] == "brewers has a four game series"

# TokenErrorResponse

def test_authz_err_resp_1():
    ter = message("TokenErrorResponse", error="access_denied", state="xyz")

    assert ter
    print ter.__dict__.items()
    assert ter["error"] == "access_denied"
    assert _eq(ter.keys(), ['state', 'error'])

def test_authz_err_resp_2():
    ter = message("TokenErrorResponse", error="access_denied",
                             error_description="brewers has a four game series",
                             foo="bar")

    assert ter
    print ter.__dict__.items()
    assert ter["error"] == "access_denied"
    assert ter["error_description"] == "brewers has a four game series"
    assert ter["foo"] == "bar"

    assert "error" in ter
    assert "error_description" in ter
    assert "foo" in ter

# AccessTokenResponse

def test_accesstokenreponse_1():
    at = message("AccessTokenResponse", access_token="SlAV32hkKG",
                token_type="Bearer", expires_in=3600)

    assert at
    atj = at.serialize(method="json")
    print atj
    assert atj == '{"access_token": "SlAV32hkKG", "token_type": "Bearer", "expires_in": 3600}'

# AccessTokenRequest

def test_extra():
    atr = message("AccessTokenRequest", grant_type="authorization_code",
                  code="SplxlOBeZQQYbYS6WxSbIA",
                  redirect_uri="https://client.example.com/cb", extra="foo")

    assert atr
    query = atr.to_urlencoded()
    print query
    assert query == "code=SplxlOBeZQQYbYS6WxSbIA&redirect_uri=https%3A%2F" \
                    "%2Fclient.example.com%2Fcb&grant_type=authorization_code&extra=foo"

    atr2 = msg_deser(query, "urlencoded", typ="AccessTokenRequest")

    print atr.to_dict()
    print atr2.to_dict()
    assert atr == atr2

# AuthorizationResponse

def test_authz_resp_1():
    atr = message("AuthorizationResponse", code="SplxlOBeZQQYbYS6WxSbIA",
                  state="Fun_state", extra="foo")

    assert atr["code"] == "SplxlOBeZQQYbYS6WxSbIA"
    assert atr["state"] == "Fun_state"
    assert atr["extra"] == "foo"

# ROPCAccessTokenRequest

#noinspection PyArgumentEqualDefault
def test_ropc_acc_token_req():
    ropc = message("ROPCAccessTokenRequest", grant_type="password",
                   username="johndoe", password="A3ddj3w")

    assert ropc["grant_type"] == "password"
    assert ropc["username"] == "johndoe"
    assert ropc["password"] == "A3ddj3w"

# CCAccessTokenRequest

def test_cc_acc_token_req():
    cc = message("CCAccessTokenRequest", scope="/foo")

    assert cc["grant_type"] == "client_credentials"
    assert cc["scope"] == "/foo"

# RefreshAccessTokenRequest

def test_ratr():
    ratr = message("RefreshAccessTokenRequest", refresh_token="ababababab",
                                     client_id="Client_id")

    assert ratr["grant_type"] == "refresh_token"
    assert ratr["refresh_token"] == "ababababab"
    assert ratr["client_id"] == "Client_id"

    assert ratr.verify()

def test_authz_load_dict():
    bib = {"scope": ["openid"],
           "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
           "redirect_uri": "http://localhost:8087authz",
           "response_type": ["code"],
           "client_id": "a1b2c3"}

    arq = message("AuthorizationRequest", **bib)

    assert arq["scope"] == bib["scope"]
    assert arq["response_type"] == bib["response_type"]
    assert arq["redirect_uri"] == bib["redirect_uri"]
    assert arq["state"] == bib["state"]
    assert arq["client_id"] == bib["client_id"]

def test_authz_req_set_json():
    argv = {"scope": ["openid"],
            "state": "id-b0be8bb64118c3ec5f70093a1174b039",
            "redirect_uri": "http://localhost:8087authz",
            "response_type": ["code"],
            "client_id": "a1b2c3"}

    arq = message("AuthorizationRequest", **argv)


    jstr = arq.serialize(method="json")

    jarq = msg_deser(jstr, "json", typ="AuthorizationRequest")

    assert jarq["scope"] == ["openid"]
    assert jarq["response_type"] == ["code"]
    assert jarq["redirect_uri"] == "http://localhost:8087authz"
    assert jarq["state"] == "id-b0be8bb64118c3ec5f70093a1174b039"
    assert jarq["client_id"] == "a1b2c3"

def test_sp_sep_list_deserializer():
    vals = sp_sep_list_deserializer("foo bar zen")
    assert len(vals) == 3
    assert _eq(vals, ["foo", "bar", "zen"])

    vals = sp_sep_list_deserializer(["foo bar zen"])
    assert len(vals) == 3
    assert _eq(vals, ["foo", "bar", "zen"])

def test_json_serializer():
    val = json_serializer({"foo": ["bar", "stool"]})
    print val
    assert val == '{"foo": ["bar", "stool"]}'

def test_json_deserializer():
    _dict = {"foo": ["bar", "stool"]}
    val = json_serializer(_dict)

    sdict = json_deserializer(val)
    assert _dict == sdict

def test_omit():
    err = message("ErrorResponse", error="invalid_request",
                  error_description="Something was missing",
                  error_uri="http://example.com/error_message.html")

    ue_str = err.to_urlencoded()
    del err["error_uri"]
    ueo_str = err.to_urlencoded()

    assert ue_str != ueo_str
    assert "error_message" not in ueo_str
    assert "error_message" in ue_str

def test_missing_required():
    err = message("ErrorResponse")
    assert "error" not in err

    raises(MissingRequiredAttribute, "err.to_urlencoded()")

def test_to_urlencoded():
    atr = message("AccessTokenResponse", 
        access_token="2YotnFZFEjr1zCsicMWpAA",
        token_type="example",
        expires_in=3600,
        refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
        example_parameter="example_value",
        scope=["inner", "outer"])

    assert _eq(atr["scope"], ["inner", "outer"])

    uec = atr.to_urlencoded()
    print uec
    assert "inner+outer" in uec

def test_to_urlencoded_extended_omit():
    atr = message("AccessTokenResponse", 
        access_token="2YotnFZFEjr1zCsicMWpAA",
        token_type="example",
        expires_in=3600,
        refresh_token="tGzv3JOkF0XG5Qx2TlKWIA",
        example_parameter="example_value",
        scope=["inner", "outer"],
        extra=["local", "external"],
        level=3)

    uec = atr.to_urlencoded()
    print uec
    assert "level=3" in uec
    assert "example_parameter=example_value" in uec
    assert "extra=local" in uec
    assert "extra=external" in uec
    del atr["extra"]
    ouec = atr.to_urlencoded()
    print ouec
    assert "level=3" in ouec
    assert "example_parameter=example_value" in ouec
    assert "extra=local" not in ouec
    assert uec != ouec
    assert len(uec) == (len(ouec) + len("extra=local") +
                        len("extra=external") + 2)

    atr2 = msg_deser(uec, "urlencoded", typ="AccessTokenResponse")
    print atr2.keys()
    assert _eq(atr2.keys(),['access_token', 'expires_in', 'token_type',
                            'scope', 'refresh_token', 'level',
                            'example_parameter', 'extra'])

    atr3 = msg_deser(ouec, "urlencoded", typ="AccessTokenResponse")
    print atr3.keys()
    assert _eq(atr3.keys(),['access_token', 'expires_in', 'token_type',
                            'scope', 'refresh_token', 'level',
                            'example_parameter'])

##noinspection PyUnusedLocal
#def test_to_urlencoded_to_many_values():
#    uec = "access_token=2YotnFZFEjr1zCsicMWpAA+AAA111BBB222CCC333"
#    raises(ValueError, "AccessTokenResponse.set_urlencoded(uec)")

#noinspection PyUnusedLocal
def test_to_set_json():
    """

    """
    item = Message("CLASS", CLASS_SPEC, req_str="Fair", opt_str="game",
                       opt_int=9, opt_str_list=["one", "two"],
                       req_str_list=["spike", "lee"],
                       opt_json='{"ford": "green"}')

    jso = item.serialize(method="json")
    print jso
    item2 = Message("CLASS", CLASS_SPEC).deserialize(jso, "json")
    print item2
    assert _eq(item2.keys(),['opt_str', 'req_str', 'opt_json', 'req_str_list',
                             'opt_str_list', 'opt_int'])

    jso_1 = '{"req_str": "Fair", "req_str_list": ["spike", "lee"], "opt_int": [9]}'

    item3 = Message("CLASS", CLASS_SPEC).deserialize(jso_1, "json")

    assert _eq(item3.keys(),['req_str', 'req_str_list', 'opt_int'])
    assert item3["opt_int"] == 9

    jso_2 = '{"req_str": "Fair", "req_str_list": ["spike", "lee"], "opt_int": [9, 10]}'
    raises(TooManyValues, 'Message("CLASS", CLASS_SPEC).deserialize(jso_2, "json")')

    jso_3 = '{"req_str": "Fair", "req_str_list": ["spike", "lee"], "extra": "out"}'
    item4 = Message("CLASS", CLASS_SPEC).deserialize(jso_3, "json")

    print item4
    assert _eq(item4.keys(),['req_str', 'req_str_list', 'extra'])
    assert item4["extra"] == "out"

    item4 = Message("CLASS", CLASS_SPEC).deserialize(jso_3, "json")

    print item4
    assert _eq(item4.keys(),['req_str', 'req_str_list', 'extra'])
    assert item4["extra"] == "out"

def test_to_from_jwt():
    item = Message("CLASS", CLASS_SPEC, req_str="Fair", opt_str="game",
                       opt_int=9, opt_str_list=["one", "two"],
                       req_str_list=["spike", "lee"],
                       opt_json='{"ford": "green"}')

    jws = item.to_jwt({"hmac":["A1B2C3D4"]}, "HS256")

    print jws

    jitem = Message("CLASS", CLASS_SPEC).from_jwt(jws,
                                                  key={".":{"hmac":["A1B2C3D4"]}})

    print jitem.keys()

    assert _eq(jitem.keys(), ['opt_str', 'req_str', 'opt_json',
                              'req_str_list', 'opt_str_list', 'opt_int'])


def test_TokenRevocationRequest():
    trr = message("TokenRevocationRequest", token="token")
    assert trr.verify()

def test_message():
    _dict = {"req_str":"Fair", "opt_str":"game", "opt_int":9,
             "opt_str_list":["one", "two"], "req_str_list":["spike", "lee"],
             "opt_json":'{"ford": "green"}'}

    cls = Message("CLASS", CLASS_SPEC, **_dict)
    cls.verify()
    assert _eq(cls.keys(), ['opt_str', 'req_str', 'opt_json',
                            'req_str_list', 'opt_str_list', 'opt_int'])

    _dict = {"req_str":"Fair", "opt_str":"game", "opt_int":9,
             "opt_str_list":["one", "two"], "req_str_list":["spike", "lee"],
             "opt_json":'{"ford": "green"}', "extra":"internal"}

    cls = Message("CLASS", CLASS_SPEC, **_dict)
    cls.verify()
    print cls.keys()
    assert _eq(cls.keys(), ['opt_str', 'req_str', 'extra', 'opt_json',
                            'req_str_list', 'opt_str_list', 'opt_int'])

    _dict = {"req_str":"Fair", "opt_str":"game", "opt_int":9,
             "opt_str_list":["one", "two"], "req_str_list":["spike", "lee"]}

    cls = Message("CLASS", CLASS_SPEC, **_dict)
    cls.verify()
    assert _eq(cls.keys(), ['opt_str', 'req_str', 'req_str_list',
                            'opt_str_list', 'opt_int'])


def test_request():
    req = Message("CLASS", CLASS_SPEC, req_str="Fair",
                  req_str_list=["game"]).request("http://example.com")

    assert req == "http://example.com?req_str=Fair&req_str_list=game"

def test_multiple_response_types():
    ar = message("AuthorizationRequest", response_type=["code", "token"],
                 client_id = "foobar")
    ue = ar.to_urlencoded()
    print ue
    assert ue == "response_type=code+token&client_id=foobar"

    are = msg_deser(ue, "urlencoded", "AuthorizationRequest")
    assert _eq(are.keys(), ["response_type", "client_id"])
    assert _eq(are["response_type"], ["code", "token"])

def test_multiple_scopes():
    ar = message("AuthorizationRequest", response_type=["code", "token"],
                 client_id = "foobar", scope=["openid", "foxtrot"])
    ue = ar.to_urlencoded()
    print ue
    assert ue == "scope=openid+foxtrot&response_type=code+token&client_id=foobar"

    are = msg_deser(ue, "urlencoded", "AuthorizationRequest")
    assert _eq(are.keys(), ["response_type", "client_id", "scope"])
    assert _eq(are["response_type"], ["code", "token"])
    assert _eq(are["scope"], ["openid", "foxtrot"])
