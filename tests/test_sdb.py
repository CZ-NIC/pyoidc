from oic.utils.time_util import utc_time_sans_frac

__author__ = 'rohe0002'

import time

from pytest import raises

from oic.utils.sdb import SessionDB, AuthnEvent
from oic.utils.sdb import ExpiredToken
from oic.oic.message import AuthorizationRequest
from oic.oic.message import OpenIDRequest

from utils_for_tests import _eq

#from oic.oauth2 import message

AREQ = AuthorizationRequest(response_type="code", client_id="client1",
                            redirect_uri="http://example.com/authz",
                            scope=["openid"], state="state000")

AREQN = AuthorizationRequest(response_type="code", client_id="client1",
                             redirect_uri="http://example.com/authz",
                             scope=["openid"], state="state000",
                             nonce="something")

OIDR = OpenIDRequest(response_type="code", client_id="client1",
                     redirect_uri="http://example.com/authz", scope=["openid"],
                     state="state000")

OAUTH2_AREQ = AuthorizationRequest(response_type="code",
                                   client_id="client1",
                                   redirect_uri="http://example.com/authz",
                                   scope=["openid"], state="state000")

BASE_URL = "https://exampl.com/"


def test_token():
    sdb = SessionDB(BASE_URL)
    sid = sdb.token.key(areq=AREQ)
    assert len(sid) == 56

    sdb = SessionDB(BASE_URL, {"a": "b"})
    sid = sdb.token.key(areq=AREQ)
    assert len(sid) == 56


def test_new_token():
    sdb = SessionDB(BASE_URL)
    sid = sdb.token.key(areq=AREQ)
    assert len(sid) == 56

    code2 = sdb.token('T', sid=sid)
    assert len(sid) == 56

    code3 = sdb.token(ttype="", prev=code2)
    assert code2 != code3
    
    sid2 = sdb.token.key(areq=AREQ, user="jones")
    assert len(sid2) == 56
    assert sid != sid2


def test_type_and_key():
    sdb = SessionDB(BASE_URL)
    sid = sdb.token.key(areq=AREQ)
    code = sdb.token(sid=sid)
    print sid
    part = sdb.token.type_and_key(code)
    print part
    assert part[0] == "A"
    assert part[1] == sid


def test_setitem():
    sdb = SessionDB(BASE_URL)
    sid = sdb.token.key(areq=AREQ)
    code = sdb.token(sid=sid)

    sdb[sid] = {"indo": "china"}

    info = sdb[sid]
    assert info == {"indo": "china"}

    info = sdb[code]
    assert info == {"indo": "china"}

    raises(KeyError, 'sdb["abcdefghijklmnop"]')


def test_update():
    sdb = SessionDB(BASE_URL)
    sid = sdb.token.key(areq=AREQ)
    code = sdb.token(sid=sid)

    raises(KeyError, 'sdb.update(sid, "indo", "nebue")')
    raises(KeyError, 'sdb.update(code, "indo", "nebue")')

    sdb[sid] = {"indo": "china"}

    sdb.update(sid, "indo", "nebue")
    sdb.update(code, "indo", "second")

    raises(KeyError, 'sdb.update("abcdefghijklmnop", "indo", "bar")')

    #noinspection PyUnusedLocal
    sid2 = sdb.token.key(areq=AREQ)

    raises(KeyError, 'sdb.update(sid2, "indo", "bar")')


def test_create_authz_session():
    sdb = SessionDB(BASE_URL)
    ae = AuthnEvent("uid")
    sid = sdb.create_authz_session(ae, AREQ)
    sdb.do_sub(sid)

    info = sdb[sid]
    print info
    assert info["oauth_state"] == "authz"

    sdb = SessionDB(BASE_URL)
    ae = AuthnEvent("sub")
    # Missing nonce property
    sid = sdb.create_authz_session(ae, OAUTH2_AREQ)
    info = sdb[sid]
    print info
    assert info["oauth_state"] == "authz"

    ae = AuthnEvent("sub")
    sid2 = sdb.create_authz_session(ae, AREQN)

    info = sdb[sid2]
    print info
    assert info["nonce"] == "something"

    sid3 = sdb.create_authz_session(ae, AREQN, id_token="id_token")

    info = sdb[sid3]
    print info
    assert info["id_token"] == "id_token"

    sid4 = sdb.create_authz_session(ae, AREQN, oidreq=OIDR)

    info = sdb[sid4]
    print info
    assert "id_token" not in info
    assert "oidreq" in info


def test_create_authz_session_with_sector_id():
    sdb = SessionDB(BASE_URL, seed="foo")
    ae = AuthnEvent("sub")
    sid5 = sdb.create_authz_session(ae, AREQN, oidreq=OIDR)
    sdb.do_sub(sid5, "http://example.com/si.jwt", "pairwise")

    info_1 = sdb[sid5]
    print info_1
    assert "id_token" not in info_1
    assert "oidreq" in info_1
    assert info_1["sub"] != "sub"
    user_id1 = info_1["sub"]

    sdb.do_sub(sid5, "http://example.net/si.jwt", "pairwise")

    info_2 = sdb[sid5]
    print info_2
    assert info_2["sub"] != "sub"
    assert info_2["sub"] != user_id1


def test_upgrade_to_token():
    sdb = SessionDB(BASE_URL)
    ae1 = AuthnEvent("sub")
    sid = sdb.create_authz_session(ae1, AREQ)
    grant = sdb[sid]["code"]
    _dict = sdb.upgrade_to_token(grant)

    print _dict.keys()
    assert _eq(_dict.keys(), ['authn_event', 'code', 'authzreq', 'revoked',
                              'access_token', 'token_expires_at', 'expires_in',
                              'token_type', 'state', 'redirect_uri',
                              'code_used', 'client_id', 'scope', 'oauth_state',
                              'refresh_token', 'access_token_scope'])

    raises(Exception, 'sdb.upgrade_to_token(grant)')

    raises(Exception, 'sdb.upgrade_to_token(_dict["access_token"]')

    sdb = SessionDB(BASE_URL)
    ae2 = AuthnEvent("another_user_id")
    sid = sdb.create_authz_session(ae2, AREQ)
    grant = sdb[sid]["code"]

    _dict = sdb.upgrade_to_token(grant, id_token="id_token", oidreq=OIDR)
    print _dict.keys()
    assert _eq(_dict.keys(), ['authn_event', 'code', 'authzreq', 'revoked',
                              'oidreq', 'access_token', 'id_token',
                              'token_expires_at', 'expires_in', 'token_type',
                              'state', 'redirect_uri', 'code_used', 'client_id',
                              'scope', 'oauth_state', 'refresh_token',
                              'access_token_scope'])

    assert _dict["id_token"] == "id_token"
    assert _dict["oidreq"].type() == "OpenIDRequest"
    _ = _dict["access_token"]
    raises(Exception, 'sdb.upgrade_to_token(token)')


def test_refresh_token():
    sdb = SessionDB(BASE_URL)
    ae = AuthnEvent("sub")
    sid = sdb.create_authz_session(ae, AREQ)
    grant = sdb[sid]["code"]
    _dict = sdb.upgrade_to_token(grant)
    dict1 = _dict.copy()

    rtoken = _dict["refresh_token"]
    time.sleep(1)
    dict2 = sdb.refresh_token(rtoken)
    print dict2
    
    assert dict1["token_expires_at"] != dict2["token_expires_at"]
    assert dict1["access_token"] != dict2["access_token"]

    raises(Exception, 'sdb.refresh_token(dict2["access_token"])')


def test_is_valid():
    sdb = SessionDB(BASE_URL)
    ae1 = AuthnEvent("sub")
    sid = sdb.create_authz_session(ae1, AREQ)
    grant = sdb[sid]["code"]

    assert sdb.is_valid(grant)

    _dict = sdb.upgrade_to_token(grant)
    assert sdb.is_valid(grant) is False
    token1 = _dict["access_token"]
    assert sdb.is_valid(token1)

    rtoken = _dict["refresh_token"]
    assert sdb.is_valid(rtoken)

    dict2 = sdb.refresh_token(rtoken)
    token2 = dict2["access_token"]
    assert sdb.is_valid(token2)

    # replace refresh_token

    dict2["refresh_token"] = token2
    assert sdb.is_valid(rtoken) is False
    
    # mess with the time-line

    dict2["token_expires_at"] = utc_time_sans_frac() - 86400
    assert sdb.is_valid(token2) is False

    # replace access_token

    dict2["access_token"] = token1
    assert sdb.is_valid(token2) is False

    ae = AuthnEvent("another:user")
    sid = sdb.create_authz_session(ae, AREQ)
    grant = sdb[sid]["code"]

    gdict = sdb[grant]
    gdict["token_expires_at"] = utc_time_sans_frac() - 86400
    assert sdb.is_valid(grant) is False


def test_revoke_token():
    sdb = SessionDB(BASE_URL)
    ae1 = AuthnEvent("sub")
    sid = sdb.create_authz_session(ae1, AREQ)

    grant = sdb[sid]["code"]
    _dict = sdb.upgrade_to_token(grant)

    token = _dict["access_token"]
    rtoken = _dict["refresh_token"]
    
    assert sdb.is_valid(token)

    sdb.revoke_token(token)
    assert sdb.is_valid(token) is False

    dict2 = sdb.refresh_token(rtoken)
    token = dict2["access_token"]
    assert sdb.is_valid(token)

    sdb.revoke_token(rtoken)
    assert sdb.is_valid(rtoken) is False

    raises(ExpiredToken, 'sdb.refresh_token(rtoken)')

    assert sdb.is_valid(token)

    # --- new token ----

    sdb = SessionDB(BASE_URL)
    ae2 = AuthnEvent("sub")
    sid = sdb.create_authz_session(ae2, AREQ)

    grant = sdb[sid]["code"]
    sdb.revoke_token(grant)
    assert sdb.is_valid(grant) is False


def test_sub_to_authn_event():
    sdb = SessionDB(BASE_URL)
    ae2 = AuthnEvent("sub", time_stamp=time.time())
    sid = sdb.create_authz_session(ae2, AREQ)
    sub = sdb.do_sub(sid)

    # given the sub find out weather the authn event is still valid

    sids = sdb.get_sids_by_sub(sub)
    ae = sdb[sids[0]]["authn_event"]
    assert ae.valid()

if __name__ == "__main__":
    test_sub_to_authn_event()
