__author__ = 'rohe0002'

import hmac
import hashlib
import time
import random
import base64
from oic import oauth2
from oic.oauth2 import MissingRequiredAttribute

from pytest import raises

def test_authz_req_urlencoded_1():
    ar = oauth2.AuthorizationRequest(["code"], "foobar")
    ue = ar.get_urlencoded()
    print ue
    assert ue == "response_type=code&client_id=foobar"

def test_authz_req_urlencoded_2():
    ar = oauth2.AuthorizationRequest(["code"], "foobar",
                                     "http://foobar.example.com/oaclient",
                                     state="cold")
    ue = ar.get_urlencoded()
    print ue
    assert ue == "state=cold&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar"

def test_authz_req_urlencoded_3():
    ar = oauth2.AuthorizationRequest(["token"],
                                    "s6BhdRkqt3",
                                    "https://client.example.com/cb",
                                    state="xyz")
    ue = ar.get_urlencoded()
    print ue
    assert ue == "state=xyz&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&response_type=token&client_id=s6BhdRkqt3"

def test_authz_req_urlencoded_4():
    ar = oauth2.AuthorizationRequest(["code"], "foobar")
    urlencoded = ar.get_urlencoded()
    ar2 = oauth2.AuthorizationRequest.set_urlencoded(urlencoded)

    print ar
    print ar2
    
    for attr in ar.c_attributes.keys():
        assert getattr(ar, attr) == getattr(ar2, attr)
    
def test_authz_req_urlencoded_5():
    ar = oauth2.AuthorizationRequest(["code"], "foobar",
                                     "http://foobar.example.com/oaclient",
                                     ["foo", "bar"],
                                     state="cold")

    ue = ar.get_urlencoded()
    print ue
    assert ue == "scope=foo+bar&state=cold&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar"

def test_authz_req_urlencoded_6():
    ar = oauth2.AuthorizationRequest(["code"], "foobar",
                                     "http://foobar.example.com/oaclient",
                                     ["foo", "bar"],
                                     state="cold")

    urlencoded = ar.get_urlencoded()
    ar2 = oauth2.AuthorizationRequest.set_urlencoded(urlencoded)

    for attr in ar.c_attributes.keys():
        assert getattr(ar, attr) == getattr(ar2, attr)

def test_authz_req_urlencoded_7():
    ar = oauth2.AuthorizationRequest(["code"])
    raises(MissingRequiredAttribute, ar.verify)

def test_authz_req_urlencoded_8():
    ar = oauth2.AuthorizationRequest([10], "foobar",
                                     "http://foobar.example.com/oaclient",
                                     ["foo", "bar"],
                                     state="cold")

    raises(ValueError, ar.verify)

def test_authz_req_urlencoded_9():
    txt = "scope=foo+bar&state=-11&redirect_uri=http%3A%2F%2Ffoobar.example.com%2Foaclient&response_type=code&client_id=foobar"

    ar = oauth2.AuthorizationRequest.set_urlencoded(txt)
    print ar
    assert ar.state == "-11"

def test_authz_req_urlencoded_10():
    txt = "scope=openid&state=id-6a3fc96caa7fd5cb1c7d00ed66937134&redirect_uri=http%3A%2F%2Flocalhost%3A8087authz&response_type=code&client_id=a1b2c3"

    ar = oauth2.AuthorizationRequest.set_urlencoded(txt)
    print ar
    assert ar.scope == ["openid"]
    assert ar.response_type == ["code"]


def test_authz_req_json_1():
    ar = oauth2.AuthorizationRequest(["code"], "foobar")
    js = ar.get_json()
    print js
    assert js == '{"response_type": ["code"], "client_id": "foobar"}'

def test_authz_req_json_2():
    ar = oauth2.AuthorizationRequest(["code"], "foobar",
                                     "http://foobar.example.com/oaclient",
                                     state="cold")
    ue = ar.get_json()
    print ue
    assert ue == '{"state": "cold", "redirect_uri": "http://foobar.example.com/oaclient", "response_type": ["code"], "client_id": "foobar"}'

def test_authz_req_urlencoded_3():
    ar = oauth2.AuthorizationRequest(["token"],
                                    "s6BhdRkqt3",
                                    "https://client.example.com/cb",
                                    state="xyz")
    ue = ar.get_json()
    print ue
    assert ue == '{"state": "xyz", "redirect_uri": "https://client.example.com/cb", "response_type": ["token"], "client_id": "s6BhdRkqt3"}'

def test_authz_req_urlencoded_4():
    ar = oauth2.AuthorizationRequest(["code"], "foobar")
    jtxt = ar.get_json()
    ar2 = oauth2.AuthorizationRequest.set_json(jtxt)

    print ar
    print ar2

    for attr in ar.c_attributes.keys():
        assert getattr(ar, attr) == getattr(ar2, attr)

def test_authz_req_x1():
    query = 'redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauthz&response_type=code&client_id=0123456789'

    ar = oauth2.AuthorizationRequest.set_urlencoded(query)

    print ar

    assert ar.verify()

# AuthorizationErrorResponse

def test_authz_err_resp_1():
    aer = oauth2.AuthorizationErrorResponse(error="access_denied", state="xyz")

    assert aer
    print aer.__dict__.items()
    assert aer.error == "access_denied"
    assert aer.state == "xyz"
    assert aer.c_extension == {}

def test_authz_err_resp_2():
    aer = oauth2.AuthorizationErrorResponse(error="access_denied",
                            error_description="brewers has a four game series",
                            foo="bar")

    assert aer
    print aer.__dict__.items()
    assert aer.error == "access_denied"
    assert aer.error_description == "brewers has a four game series"
    assert aer.c_extension == {'foo': 'bar'}

# TokenErrorResponse

def test_authz_err_resp_1():
    ter = oauth2.TokenErrorResponse(error="access_denied", state="xyz")

    assert ter
    print ter.__dict__.items()
    assert ter.error == "access_denied"
    assert ter.c_extension == {'state': 'xyz'}

def test_authz_err_resp_2():
    ter = oauth2.TokenErrorResponse(error="access_denied",
                            error_description="brewers has a four game series",
                            foo="bar")

    assert ter
    print ter.__dict__.items()
    assert ter.error == "access_denied"
    assert ter.error_description == "brewers has a four game series"
    assert ter.c_extension == {'foo': 'bar'}

# AccessTokenResponse

def test_accesstokenreponse_1():
    at = oauth2.AccessTokenResponse("SlAV32hkKG", "8xLOxBtZp8", 3600)

    assert at
    atj = at.get_json()
    print atj
    assert atj == '{"access_token": "SlAV32hkKG", "token_type": "8xLOxBtZp8", "expires_in": 3600}'

# AccessTokenRequest

def test_extra():
    atr = oauth2.AccessTokenRequest("authorization_code",
                                    "SplxlOBeZQQYbYS6WxSbIA",
                                    "https://client.example.com/cb",
                                    "client_id",
                                    extra="foo")

    assert atr
    query = atr.get_urlencoded(True)
    print query
    assert query == "code=SplxlOBeZQQYbYS6WxSbIA&grant_type=authorization_code&client_id=client_id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&extra=foo"

    atr2 = oauth2.AccessTokenRequest.set_urlencoded(query, True)
    print atr2.c_extension
    assert atr2.c_extension == {"extra": "foo"}

# AuthorizationResponse

def test_authz_resp_1():
    atr = oauth2.AuthorizationResponse("SplxlOBeZQQYbYS6WxSbIA",
                                        "Fun_state",
                                        extra="foo")

    assert atr.code == "SplxlOBeZQQYbYS6WxSbIA"
    assert atr.state == "Fun_state"
    print atr.c_extension
    assert atr.c_extension == {"extra": "foo"}

# ROPCAccessTokenRequest

#noinspection PyArgumentEqualDefault
def test_ropc_acc_token_req():
    ropc = oauth2.ROPCAccessTokenRequest("password", "johndoe", "A3ddj3w")

    assert ropc.grant_type == "password"
    assert ropc.username == "johndoe"
    assert ropc.password == "A3ddj3w"

# CCAccessTokenRequest

def test_cc_acc_token_req():
    cc = oauth2.CCAccessTokenRequest(scope="/foo")

    assert cc.grant_type == "client_credentials"
    assert cc.scope == "/foo"

# RefreshAccessTokenRequest

def test_ratr():
    ratr = oauth2.RefreshAccessTokenRequest(refresh_token="ababababab",
                                            client_id="Client_id")

    assert ratr.grant_type == "refresh_token"
    assert ratr.refresh_token == "ababababab"
    assert ratr.client_id == "Client_id"

    assert ratr.verify()

def test_crypt():
    crypt = oauth2.Crypt("4-amino-1H-pyrimidine-2-one")
    ctext = crypt.encrypt("Cytosine")
    plain = crypt.decrypt(ctext)
    print plain
    assert plain == 'Cytosine        '

    ctext = crypt.encrypt("cytidinetriphosp")
    plain = crypt.decrypt(ctext)

    assert plain == 'cytidinetriphosp'

def test_crypt2():
    db = {}
    csum = hmac.new("secret", digestmod=hashlib.sha224)
    csum.update("%s" % time.time())
    csum.update("%f" % random.random())
    txt = csum.digest() # 28 bytes long, 224 bits
    print len(txt)
    db[txt] = "foobar"
    txt = "%saces" % txt # another 4 bytes
    #print len(txt), txt
    crypt = oauth2.Crypt("4-amino-1H-pyrimidine-2-one")
    ctext = crypt.encrypt(txt)
    onthewire = base64.b64encode(ctext)
    #print onthewire
    plain = crypt.decrypt(base64.b64decode(onthewire))
    #print len(plain), plain
    #assert plain == txt
    assert plain.endswith("aces")
    assert db[plain[:-4]] == "foobar"

def test_authz_load_dict():
    bib = {"scope": ["openid"],
           "state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
           "redirect_uri": "http://localhost:8087authz",
           "response_type": ["code"],
           "client_id": "a1b2c3"}

    arq = oauth2.AuthorizationRequest(**bib)

    assert arq.scope == bib["scope"]
    assert arq.response_type == bib["response_type"]
    assert arq.redirect_uri == bib["redirect_uri"]
    assert arq.state == bib["state"]
    assert arq.client_id == bib["client_id"]

def test_authz_req_set_json():
    argv = {"scope": ["openid"],
            "state": "id-b0be8bb64118c3ec5f70093a1174b039",
            "redirect_uri": "http://localhost:8087authz",
            "response_type": ["code"],
            "client_id": "a1b2c3"}

    arq = oauth2.AuthorizationRequest(**argv)


    jstr = arq.get_json()

    jarq = oauth2.AuthorizationRequest.set_json(jstr)

    assert jarq.scope == ["openid"]
    assert jarq.response_type == ["code"]
    assert jarq.redirect_uri == "http://localhost:8087authz"
    assert jarq.state == "id-b0be8bb64118c3ec5f70093a1174b039"
    assert jarq.client_id == "a1b2c3"
