import base64
import datetime
import hashlib
import hmac
import json
import random
import time

import pytest
from freezegun import freeze_time

from oic.oic.message import AuthorizationRequest
from oic.oic.message import OpenIDRequest
from oic.utils.sdb import AccessCodeUsed
from oic.utils.sdb import AuthnEvent
from oic.utils.sdb import Crypt
from oic.utils.sdb import DefaultToken
from oic.utils.sdb import DictRefreshDB
from oic.utils.sdb import ExpiredToken
from oic.utils.sdb import WrongTokenType

__author__ = 'rohe0002'

AREQ = AuthorizationRequest(response_type="code", client_id="client1",
                            redirect_uri="http://example.com/authz",
                            scope=["openid"], state="state000")

AREQN = AuthorizationRequest(response_type="code", client_id="client1",
                             redirect_uri="http://example.com/authz",
                             scope=["openid"], state="state000",
                             nonce="something")

AREQO = AuthorizationRequest(response_type="code", client_id="client1",
                             redirect_uri="http://example.com/authz",
                             scope=["openid", "offlien_access"],
                             prompt="consent", state="state000")

OIDR = OpenIDRequest(response_type="code", client_id="client1",
                     redirect_uri="http://example.com/authz", scope=["openid"],
                     state="state000")


def _eq(l1, l2):
    return set(l1) == set(l2)


class TestAuthnEvent(object):
    """Tests for AuthnEvent class."""

    def test_from_json(self):
        dic = {'uid': 'uid', 'salt': 'salt', 'authn_time': 1000, 'valid_until': 1500}
        ae = AuthnEvent.from_json(json.dumps(dic))
        assert ae.uid == 'uid'
        assert ae.salt == 'salt'
        assert ae.authn_time == 1000
        assert ae.valid_until == 1500

    def test_to_json(self):
        ae = AuthnEvent('uid', 'salt', authn_time=1000, valid_until=1500)
        json_repr = ae.to_json()
        assert json.loads(json_repr) == {'uid': 'uid', 'salt': 'salt', 'authn_time': 1000,
                                         'valid_until': 1500, 'authn_info': None}


class TestDictRefreshDB(object):
    @pytest.fixture(autouse=True)
    def create_rdb(self):
        self.rdb = DictRefreshDB()

    def test_verify_token(self):
        token = self.rdb.create_token('client1', 'uid', 'openid', 'sub1',
                                      'authzreq', 'sid')
        assert self.rdb.verify_token('client1', token)
        assert self.rdb.verify_token('client2', token) is False

    def test_revoke_token(self):
        token = self.rdb.create_token('client1', 'uid', 'openid', 'sub1',
                                      'authzreq', 'sid')
        self.rdb.remove(token)
        assert self.rdb.verify_token('client1', token) is False
        assert pytest.raises(KeyError, 'self.rdb.get(token)')

    def test_get_token(self):
        assert pytest.raises(KeyError, 'self.rdb.get("token")')
        token = self.rdb.create_token('client1', 'uid', ['openid'], 'sub1',
                                      'authzreq', 'sid')
        assert self.rdb.get(token) == {'client_id': 'client1', 'sub': 'sub1',
                                       'scope': ['openid'], 'uid': 'uid',
                                       'authzreq': 'authzreq', 'sid': 'sid'}


class TestToken(object):
    @pytest.fixture(autouse=True)
    def create_token(self):
        self.token = DefaultToken("secret", "password", lifetime=60)

    def test_token(self):
        sid = self.token.key(areq=AREQ)
        assert len(sid) == 56

    def test_new_token(self):
        sid = self.token.key(areq=AREQ)
        assert len(sid) == 56

        self.token(sid=sid, ttype='T')
        assert len(sid) == 56

        sid2 = self.token.key(areq=AREQ, user="jones")
        assert len(sid2) == 56
        assert sid != sid2

    def test_type_and_key(self):
        sid = self.token.key(areq=AREQ)
        code = self.token(sid=sid)
        part = self.token.type_and_key(code)
        assert part[0] == "A"
        assert part[1] == sid

    def test_expired_fresh(self):
        factory = DefaultToken('secret', 'password', lifetime=60)
        token = factory(sid="abc", ttype="T")
        assert factory.is_expired(token) is False

    def test_expired_stale(self):
        initial_datetime = datetime.datetime(2018, 2, 5, 10, 0, 0, 0)
        final_datetime = datetime.datetime(2018, 2, 5, 10, 1, 0, 0)
        factory = DefaultToken('secret', 'password', lifetime=2)
        with freeze_time(initial_datetime) as frozen:
            token = factory(sid="abc", ttype="T")
            frozen.move_to(final_datetime)
            assert factory.is_expired(token) is True

    def test_expired_when(self):
        factory = DefaultToken('secret', 'password', lifetime=2)
        token = factory(sid="abc", ttype="T")
        when = time.time() + 5  # 5 seconds from now
        assert factory.is_expired(token, when=when) is True


class TestSessionDB(object):
    @pytest.fixture(autouse=True)
    def create_sdb(self, session_db_factory):
        self.sdb = session_db_factory("https://example.com/")

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
        self.sdb.do_sub(sid, "client_salt", "http://example.com/si.jwt",
                        "pairwise")

        info_1 = self.sdb[sid].copy()
        assert "id_token" not in info_1
        assert "oidreq" in info_1
        assert info_1["sub"] != "sub"

        self.sdb.do_sub(sid, "client_salt", "http://example.net/si.jwt",
                        "pairwise")

        info_2 = self.sdb[sid]
        assert info_2["sub"] != "sub"
        assert info_2["sub"] != info_1["sub"]

    def test_upgrade_to_token(self):
        ae1 = AuthnEvent("uid", "salt")
        sid = self.sdb.create_authz_session(ae1, AREQ)
        self.sdb[sid]['sub'] = 'sub'
        grant = self.sdb[sid]["code"]
        _dict = self.sdb.upgrade_to_token(grant)

        print(_dict.keys())
        assert _eq(list(_dict.keys()),
                   ['authn_event', 'code', 'authzreq', 'revoked',
                    'access_token', 'token_type', 'state', 'redirect_uri',
                    'code_used', 'client_id', 'scope', 'oauth_state',
                    'access_token_scope', 'sub', 'response_type'])

        # can't update again
        with pytest.raises(AccessCodeUsed):
            self.sdb.upgrade_to_token(grant)
            self.sdb.upgrade_to_token(_dict["access_token"])

    def test_upgrade_to_token_refresh(self):
        ae1 = AuthnEvent("sub", "salt")
        sid = self.sdb.create_authz_session(ae1, AREQO)
        self.sdb.do_sub(sid, ae1.salt)
        grant = self.sdb[sid]["code"]
        _dict = self.sdb.upgrade_to_token(grant, issue_refresh=True)

        print(_dict.keys())
        assert _eq(_dict.keys(),
                   ['authn_event', 'code', 'authzreq', 'revoked',
                    'access_token', 'response_type',
                    'token_type', 'state', 'redirect_uri', 'code_used',
                    'client_id', 'scope', 'oauth_state', 'access_token_scope',
                    'refresh_token', 'sub'])

        # can't update again
        with pytest.raises(AccessCodeUsed):
            self.sdb.upgrade_to_token(grant)
            self.sdb.upgrade_to_token(_dict["access_token"])

    def test_upgrade_to_token_with_id_token_and_oidreq(self):
        ae2 = AuthnEvent("another_user_id", "salt")
        sid = self.sdb.create_authz_session(ae2, AREQ)
        self.sdb[sid]['sub'] = 'sub'
        grant = self.sdb[sid]["code"]

        _dict = self.sdb.upgrade_to_token(grant, id_token="id_token",
                                          oidreq=OIDR)
        print(_dict.keys())
        assert _eq(list(_dict.keys()),
                   ['authn_event', 'code', 'authzreq', 'revoked', 'oidreq',
                    'access_token', 'id_token', 'response_type',
                    'token_type', 'state', 'redirect_uri',
                    'code_used', 'client_id', 'scope', 'oauth_state',
                    'access_token_scope', 'sub'])

        assert _dict["id_token"] == "id_token"
        assert isinstance(_dict["oidreq"], OpenIDRequest)

    def test_refresh_token(self):
        ae = AuthnEvent("uid", "salt")
        sid = self.sdb.create_authz_session(ae, AREQ)
        self.sdb[sid]['sub'] = 'sub'
        grant = self.sdb[sid]["code"]

        dict1 = self.sdb.upgrade_to_token(grant, issue_refresh=True).copy()
        rtoken = dict1["refresh_token"]
        dict2 = self.sdb.refresh_token(rtoken, AREQ['client_id'])

        assert dict1["access_token"] != dict2["access_token"]

        with pytest.raises(WrongTokenType):
            self.sdb.refresh_token(dict2["access_token"], AREQ['client_id'])

    def test_refresh_token_cleared_session(self):
        ae = AuthnEvent('uid', 'salt')
        sid = self.sdb.create_authz_session(ae, AREQ)
        self.sdb[sid]['sub'] = 'sub'
        grant = self.sdb[sid]['code']
        dict1 = self.sdb.upgrade_to_token(grant, issue_refresh=True)
        ac1 = dict1['access_token']

        # Purge the SessionDB
        self.sdb._db = {}

        rtoken = dict1['refresh_token']
        dict2 = self.sdb.refresh_token(rtoken, AREQ['client_id'])

        assert ac1 != dict2["access_token"]
        assert self.sdb.is_valid(dict2['access_token'])

    def test_is_valid(self):
        ae1 = AuthnEvent("uid", "salt")
        sid = self.sdb.create_authz_session(ae1, AREQ)
        self.sdb[sid]['sub'] = 'sub'
        grant = self.sdb[sid]["code"]

        assert self.sdb.is_valid(grant)

        sinfo = self.sdb.upgrade_to_token(grant, issue_refresh=True)
        assert not self.sdb.is_valid(grant)
        access_token = sinfo["access_token"]
        assert self.sdb.access_token.valid(access_token)

        refresh_token = sinfo["refresh_token"]
        sinfo = self.sdb.refresh_token(refresh_token, AREQ['client_id'])
        access_token2 = sinfo["access_token"]
        assert self.sdb.is_valid(access_token2)

        # The old access code should be invalid
        try:
            self.sdb.is_valid(access_token)
        except KeyError:
            pass

    def test_valid_grant(self):
        ae = AuthnEvent("another:user", "salt")
        sid = self.sdb.create_authz_session(ae, AREQ)
        grant = self.sdb[sid]["code"]

        assert self.sdb.is_valid(grant)

    def test_revoke_token(self):
        ae1 = AuthnEvent("uid", "salt")
        sid = self.sdb.create_authz_session(ae1, AREQ)
        self.sdb[sid]['sub'] = 'sub'

        grant = self.sdb[sid]["code"]
        tokens = self.sdb.upgrade_to_token(grant, issue_refresh=True)
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]

        assert self.sdb.is_valid(access_token)

        self.sdb.revoke_token(access_token)
        assert not self.sdb.is_valid(access_token)

        sinfo = self.sdb.refresh_token(refresh_token, AREQ['client_id'])
        access_token = sinfo["access_token"]
        assert self.sdb.is_valid(access_token)

        self.sdb.revoke_refresh_token(refresh_token)
        assert not self.sdb.is_valid(refresh_token)

        try:
            self.sdb.refresh_token(refresh_token, AREQ['client_id'])
        except ExpiredToken:
            pass

        assert self.sdb.is_valid(access_token)

        ae2 = AuthnEvent("sub", "salt")
        sid = self.sdb.create_authz_session(ae2, AREQ)

        grant = self.sdb[sid]["code"]
        self.sdb.revoke_token(grant)
        assert not self.sdb.is_valid(grant)

    def test_revoke_all_tokens(self):
        ae1 = AuthnEvent("uid", "salt")
        sid = self.sdb.create_authz_session(ae1, AREQ)
        self.sdb[sid]['sub'] = 'sub'

        grant = self.sdb[sid]["code"]
        tokens = self.sdb.upgrade_to_token(grant, issue_refresh=True)
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]

        self.sdb.revoke_all_tokens(access_token)
        assert not self.sdb.is_valid(access_token)
        assert not self.sdb.is_valid(refresh_token)

    def test_sub_to_authn_event(self):
        ae = AuthnEvent("sub", "salt", time_stamp=time.time())
        sid = self.sdb.create_authz_session(ae, AREQ)
        sub = self.sdb.do_sub(sid, "client_salt")

        # given the sub find out whether the authn event is still valid
        sids = self.sdb.get_sids_by_sub(sub)
        ae = self.sdb[sids[0]]["authn_event"]
        assert AuthnEvent.from_json(ae).valid()

    def test_do_sub_deterministic(self):
        ae = AuthnEvent("tester", "random_value")
        sid = self.sdb.create_authz_session(ae, AREQ)
        self.sdb.do_sub(sid, "other_random_value")

        info = self.sdb[sid]
        assert info["sub"] == '179670cdee6375c48e577317b2abd7d5cd26a5cdb1cfb7ef84af3d703c71d013'

        self.sdb.do_sub(sid, "other_random_value",
                        sector_id='http://example.com',
                        subject_type="pairwise")
        info2 = self.sdb[sid]
        assert info2["sub"] == 'aaa50d80f8780cf1c4beb39e8e126556292f5091b9e39596424fefa2b99d9c53'

        self.sdb.do_sub(sid, "another_random_value",
                        sector_id='http://other.example.com',
                        subject_type="pairwise")

        info2 = self.sdb[sid]
        assert info2["sub"] == '62fb630e29f0d41b88e049ac0ef49a9c3ac5418c029d6e4f5417df7e9443976b'

    def test_get_authentication_event_dict(self):
        self.sdb._db['123'] = {}
        self.sdb._db['123']['authn_event'] = {'uid': 'uid', 'salt': 'salt', 'authn_time': 1000, 'valid_until': 1500}
        ae = self.sdb.get_authentication_event('123')
        assert ae.uid == 'uid'
        assert ae.salt == 'salt'
        assert ae.authn_time == 1000
        assert ae.valid_until == 1500

    def test_get_authentication_event_json(self):
        self.sdb._db['123'] = {}
        self.sdb._db['123']['authn_event'] = json.dumps({'uid': 'uid', 'salt': 'salt', 'authn_time': 1000,
                                                         'valid_until': 1500})
        ae = self.sdb.get_authentication_event('123')
        assert ae.uid == 'uid'
        assert ae.salt == 'salt'
        assert ae.authn_time == 1000
        assert ae.valid_until == 1500


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
