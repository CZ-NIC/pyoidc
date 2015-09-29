import base64
import hashlib
import hmac
import random
import time

import pytest

import mock
from oic.utils.time_util import utc_time_sans_frac
from oic.utils.sdb import SessionDB, AuthnEvent, Token, WrongTokenType, Crypt, \
    AccessCodeUsed
from oic.utils.sdb import ExpiredToken
from oic.oic.message import AuthorizationRequest
from oic.oic.message import OpenIDRequest
from utils_for_tests import _eq

__author__ = 'rohe0002'

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


class TestToken(object):
    @pytest.fixture(autouse=True)
    def create_token(self):
        self.token = Token("secret", "password")

    def test_token(self):
        sid = self.token.key(areq=AREQ)
        assert len(sid) == 56

    def test_new_token(self):
        sid = self.token.key(areq=AREQ)
        assert len(sid) == 56

        code2 = self.token('T', sid=sid)
        assert len(sid) == 56

        code3 = self.token(ttype="", prev=code2)
        assert code2 != code3

        sid2 = self.token.key(areq=AREQ, user="jones")
        assert len(sid2) == 56
        assert sid != sid2

    def test_type_and_key(self):
        sid = self.token.key(areq=AREQ)
        code = self.token(sid=sid)
        part = self.token.type_and_key(code)
        assert part[0] == "A"
        assert part[1] == sid


class TestSessionDB(object):
    @pytest.fixture(autouse=True)
    def create_sdb(self):
        self.sdb = SessionDB("https://example.com/")

    def test_setitem(self):
        sid = self.sdb.token.key(areq=AREQ)
        code = self.sdb.token(sid=sid)

        self.sdb[sid] = {"indo": "china"}

        info = self.sdb[sid]
        assert info == {"indo": "china"}

        info = self.sdb[code]
        assert info == {"indo": "china"}

    def test_getitem_key_error(self):
        with pytest.raises(KeyError):
            self.sdb["abcdefghijklmnop"]

    def test_update(self):
        sid = self.sdb.token.key(areq=AREQ)
        code = self.sdb.token(sid=sid)
        self.sdb[sid] = {"indo": "china"}

        self.sdb.update(sid, "indo", "nebue")
        self.sdb.update(code, "indo", "second")

    def test_update_non_existing(self):
        sid = self.sdb.token.key(areq=AREQ)
        code = self.sdb.token(sid=sid)

        # can't update non-existing
        with pytest.raises(KeyError):
            self.sdb.update(sid, "indo", "nebue")
            self.sdb.update(code, "indo", "nebue")
            self.sdb.update("abcdefghijklmnop", "indo", "bar")

    def test_create_authz_session(self):
        ae = AuthnEvent("uid", "salt")
        sid = self.sdb.create_authz_session(ae, AREQ)
        self.sdb.do_sub(sid, "client_salt")

        info = self.sdb[sid]
        assert info["oauth_state"] == "authz"

    def test_create_authz_session_without_nonce(self):
        ae = AuthnEvent("sub", "salt")
        sid = self.sdb.create_authz_session(ae, AREQ)
        info = self.sdb[sid]
        assert info["oauth_state"] == "authz"

    def test_create_authz_session_with_nonce(self):
        ae = AuthnEvent("sub", "salt")
        sid = self.sdb.create_authz_session(ae, AREQN)
        info = self.sdb[sid]
        assert info["nonce"] == "something"

    def test_create_authz_session_with_id_token(self):
        ae = AuthnEvent("sub", "salt")
        sid = self.sdb.create_authz_session(ae, AREQN, id_token="id_token")

        info = self.sdb[sid]
        assert info["id_token"] == "id_token"

    def test_create_authz_session_with_oidreq(self):
        ae = AuthnEvent("sub", "salt")
        sid = self.sdb.create_authz_session(ae, AREQN, oidreq=OIDR)
        info = self.sdb[sid]
        assert "id_token" not in info
        assert "oidreq" in info

    def test_create_authz_session_with_sector_id(self):
        ae = AuthnEvent("sub", "salt")
        sid = self.sdb.create_authz_session(ae, AREQN, oidreq=OIDR)
        self.sdb.do_sub(sid, "client_salt", "http://example.com/si.jwt", "pairwise")

        info_1 = self.sdb[sid].copy()
        assert "id_token" not in info_1
        assert "oidreq" in info_1
        assert info_1["sub"] != "sub"

        self.sdb.do_sub(sid, "client_salt", "http://example.net/si.jwt", "pairwise")

        info_2 = self.sdb[sid]
        assert info_2["sub"] != "sub"
        assert info_2["sub"] != info_1["sub"]

    def test_upgrade_to_token(self):
        ae1 = AuthnEvent("sub", "salt")
        sid = self.sdb.create_authz_session(ae1, AREQ)
        grant = self.sdb[sid]["code"]
        _dict = self.sdb.upgrade_to_token(grant)

        assert _eq(_dict.keys(),
                   ['authn_event', 'code', 'authzreq', 'revoked',
                    'access_token', 'token_expires_at', 'expires_in',
                    'token_type', 'state', 'redirect_uri',
                    'code_used', 'client_id', 'scope', 'oauth_state',
                    'refresh_token', 'access_token_scope'])

        # can't update again
        with pytest.raises(AccessCodeUsed):
            self.sdb.upgrade_to_token(grant)
            self.sdb.upgrade_to_token(_dict["access_token"])

    def test_upgrade_to_token_with_id_token_and_oidreq(self):
        ae2 = AuthnEvent("another_user_id", "salt")
        sid = self.sdb.create_authz_session(ae2, AREQ)
        grant = self.sdb[sid]["code"]

        _dict = self.sdb.upgrade_to_token(grant, id_token="id_token",
                                          oidreq=OIDR)
        assert _eq(list(_dict.keys()),
                   ['authn_event', 'code', 'authzreq', 'revoked',
                    'oidreq', 'access_token', 'id_token',
                    'token_expires_at', 'expires_in', 'token_type',
                    'state', 'redirect_uri', 'code_used', 'client_id',
                    'scope', 'oauth_state', 'refresh_token',
                    'access_token_scope'])

        assert _dict["id_token"] == "id_token"
        assert isinstance(_dict["oidreq"], OpenIDRequest)

    def test_refresh_token(self):
        ae = AuthnEvent("sub", "salt")
        sid = self.sdb.create_authz_session(ae, AREQ)
        grant = self.sdb[sid]["code"]

        with mock.patch("time.gmtime", side_effect=[
                time.struct_time((1970, 1, 1, 10, 39, 0, 0, 0, 0)),
                time.struct_time((1970, 1, 1, 10, 40, 0, 0, 0, 0))]):
            dict1 = self.sdb.upgrade_to_token(grant).copy()
            rtoken = dict1["refresh_token"]
            dict2 = self.sdb.refresh_token(rtoken)

        assert dict1["token_expires_at"] != dict2["token_expires_at"]
        assert dict1["access_token"] != dict2["access_token"]

        with pytest.raises(WrongTokenType):
            self.sdb.refresh_token(dict2["access_token"])

    def test_is_valid(self):
        ae1 = AuthnEvent("sub", "salt")
        sid = self.sdb.create_authz_session(ae1, AREQ)
        grant = self.sdb[sid]["code"]

        assert self.sdb.is_valid(grant)

        tokens = self.sdb.upgrade_to_token(grant)
        assert not self.sdb.is_valid(grant)
        access_token = tokens["access_token"]
        assert self.sdb.is_valid(access_token)

        refresh_token = tokens["refresh_token"]
        assert self.sdb.is_valid(refresh_token)

        refreshed_tokens = self.sdb.refresh_token(refresh_token)
        access_token2 = refreshed_tokens["access_token"]
        assert self.sdb.is_valid(access_token2)

        # replace refresh_token
        refreshed_tokens["refresh_token"] = access_token2
        assert not self.sdb.is_valid(refresh_token)

        # mess with the time-line
        refreshed_tokens["token_expires_at"] = utc_time_sans_frac() - 86400
        assert not self.sdb.is_valid(access_token2)

        # replace access_token
        refreshed_tokens["access_token"] = access_token
        assert not self.sdb.is_valid(access_token2)

        ae = AuthnEvent("another:user", "salt")
        sid = self.sdb.create_authz_session(ae, AREQ)
        grant = self.sdb[sid]["code"]

        self.sdb.update(grant, "token_expires_at", utc_time_sans_frac() - 86400)
        assert not self.sdb.is_valid(grant)

    def test_revoke_token(self):
        ae1 = AuthnEvent("sub", "salt")
        sid = self.sdb.create_authz_session(ae1, AREQ)

        grant = self.sdb[sid]["code"]
        tokens = self.sdb.upgrade_to_token(grant)
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]

        assert self.sdb.is_valid(access_token)

        self.sdb.revoke_token(access_token)
        assert not self.sdb.is_valid(access_token)

        refreshed_tokens = self.sdb.refresh_token(refresh_token)
        access_token = refreshed_tokens["access_token"]
        assert self.sdb.is_valid(access_token)

        self.sdb.revoke_token(refresh_token)
        assert not self.sdb.is_valid(refresh_token)

        with pytest.raises(ExpiredToken):
            self.sdb.refresh_token(refresh_token)

        assert self.sdb.is_valid(access_token)

        ae2 = AuthnEvent("sub", "salt")
        sid = self.sdb.create_authz_session(ae2, AREQ)

        grant = self.sdb[sid]["code"]
        self.sdb.revoke_token(grant)
        assert not self.sdb.is_valid(grant)

    def test_sub_to_authn_event(self):
        ae = AuthnEvent("sub", "salt", time_stamp=time.time())
        sid = self.sdb.create_authz_session(ae, AREQ)
        sub = self.sdb.do_sub(sid, "client_salt")

        # given the sub find out whether the authn event is still valid
        sids = self.sdb.get_sids_by_sub(sub)
        ae = self.sdb[sids[0]]["authn_event"]
        assert ae.valid()

    def test_do_sub_deterministic(self):
        ae = AuthnEvent("tester", "random_value")
        sid = self.sdb.create_authz_session(ae, AREQ)
        self.sdb.do_sub(sid, "other_random_value")

        info = self.sdb[sid]
        assert info["sub"] == '179670cdee6375c48e577317b2abd7d5cd26a5cdb1cfb7ef84af3d703c71d013'

        self.sdb.do_sub(sid, "other_random_value", sector_id='http://example.com',
                        subject_type="pairwise")
        info2 = self.sdb[sid]
        assert info2["sub"] == 'aaa50d80f8780cf1c4beb39e8e126556292f5091b9e39596424fefa2b99d9c53'

        self.sdb.do_sub(sid, "another_random_value", sector_id='http://other.example.com',
                        subject_type="pairwise")

        info2 = self.sdb[sid]
        assert info2["sub"] == '62fb630e29f0d41b88e049ac0ef49a9c3ac5418c029d6e4f5417df7e9443976b'


class TestCrypt(object):
    @pytest.fixture(autouse=True)
    def create_crypt(self):
        self.crypt = Crypt("4-amino-1H-pyrimidine-2-one")

    def test_encrypt_decrypt(self):
        ctext = self.crypt.encrypt("Cytosine")
        plain = self.crypt.decrypt(ctext).decode("utf-8")
        assert plain == 'Cytosine        '

        ctext = self.crypt.encrypt("cytidinetriphosp")
        plain = self.crypt.decrypt(ctext).decode("utf-8")

        assert plain == 'cytidinetriphosp'

    def test_crypt_with_b64(self):
        db = {}
        msg = "secret{}{}".format(time.time(), random.random())
        csum = hmac.new(msg.encode("utf-8"), digestmod=hashlib.sha224)
        txt = csum.digest()  # 28 bytes long, 224 bits
        db[txt] = "foobar"
        txt = txt + b"aces"  # another 4 bytes

        ctext = self.crypt.encrypt(txt)
        onthewire = base64.b64encode(ctext)
        plain = self.crypt.decrypt(base64.b64decode(onthewire))
        assert plain.endswith(b"aces")
        assert db[plain[:-4]] == "foobar"
