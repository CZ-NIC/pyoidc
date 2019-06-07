import time

import pytest

from oic import rndstr
from oic.extension.token import JWTToken
from oic.oauth2 import AuthorizationRequest
from oic.oic import OpenIDRequest
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.sdb import AccessCodeUsed
from oic.utils.sdb import AuthnEvent
from oic.utils.sdb import DefaultToken
from oic.utils.sdb import DictSessionBackend
from oic.utils.sdb import ExpiredToken
from oic.utils.sdb import SessionDB

__author__ = 'roland'


def _eq(l1, l2):
    return set(l1) == set(l2)


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

JWKS = {"keys": [
    {
        "d": "vT9bnSZ63uIdaVsmZjrbmcvrDZG-_qzVQ1KmrSSC398sLJiyaQKRPkmBRvV"
             "-MGxW1MVPeCkhnSULCRgtqHq"
             "-zQxMeCviSScHTKOuDYJfwMB5qdOE3FkuqPMsEVf6EXYaSd90"
             "-O6GOA88LBCPNR4iKxsrQ6LNkawwiJoPw7muK3TbQk9HzuznF8WDkt72CQFxd4eT"
             "6wJ97xpaIgxZce0oRmFcLYkQ4A0pgVhF42zxJjJDIBj_ZrSl5_qZIgiE76PV4hjH"
             "t9Nv4ZveabObnNbyz9YOiWHiOLdYZGmixHuauM98NK8udMxI6IuOkRypFhJzaQZF"
             "wMroa7ZNZF-mm78VYQ",
        "dp":
            "wLqivLfMc0FBhGFFRTb6WWzDpVZukcgOEQGb8wW3knmNEpgch699WQ4ZY_ws1xSbv"
            "QZtbx7MaIBXpn3qT1LYZosoP5oHVTAvdg6G8I7zgWyqj-nG4evciuoeAa1Ff52h4-"
            "J1moZ6FF2GelLdjXHoCbjIBjz_VljelSqOk5Sh5HU",
        "dq": "KXIUYNfDxwxv3A_w1t9Ohm92gOs-UJdI3_IVpe4FauCDrJ4mqgsnTisA15KY"
              "-9fCEvKfqG571WK6EKpBcxaRrqSU0ekpBvgJx8o3MGlqXWj-Lw0co8N9_"
              "-fo1rYx_8g-wCRrm5zeA5pYJdwdhOBnmKOqw_GsXJEcYeUod1xkcfU",
        "e": "AQAB",
        "ext": "true",
        "key_ops": "sign",
        "kty": "RSA",
        "n": "wl0DPln-EFLqr_Ftn6A87wEQAUVbpZsUTN2OCEsJV0nhlvmX3GUzyZx5UXdlM3Dz68PfUWCgfx67Il6sURqWVCnjnU-_gr3GeDyzedj"
             "-lZejnBx-lEy_3j6B98SbcDfkJF6saXnPd7_kgilJT1_g-EVI9ifFB1cxZXHCd2WBeRABSCprAlCglF-YmnUeeDs5K32z2ckVjadF9B"
             "G27CO5UfNq0K8jI9Yj_coOhM9dRNrQ9UVZNdQVG-bAIDhB2y2o3ASGwqchHouIxv5YZNGS0SMJL5t0edh483q1tSWPqBw-ZeryLztOe"
             "dBBzSuJk7QDmL1B6B7KKUIrlUYJmVsYzw",
        "p": "6MEg5Di_IFiPGKvMFRjyx2t7YAOQ4KfdIkU_Khny1t1eCG5O07omPe_jLU8I5fPaD5F5HhWExLNureHD4K6LB18JPE3VE8chQROiRSN"
             "PZo1-faUvHu-Dy0pr7I-TS8pl_P3vop1KelIbGwXhzPIRKQMqCEKi3tLJt4R_MQ18Dx0",
        "q": "1cZVPpUbf4p5n4cMv_kERCPh3cieMs4aVojgh3feAiJiLwWWL9Pc43oJUekK44aWMnbs68Y4kqXtc52PMtBDzVp0Gjt0lCY3M7MYRVI"
             "4JhtknqvQynMKQ2nKs3VldvVfY2SxyUmnRyEolQUGRA7rRMUyPb4AXhSR7oroRrJD59s",
        "qi": "50PhyaqbLSczhipWiYy149sLsGlx9cX0tnGMswy1JLam7nBvH4"
              "-MWB2oGwD2hmG-YN66q-xXBS9CVDLZZrj1sonRTQPtWE"
              "-zuZqds6_NVlk2Ge4_IAA3TZ9tvIfM5FZVTOQsExu3_LX8FGCspWC1R"
              "-zDqT45Y9bpaCwxekluO7Q",
        'kid': 'sign1'
    }, {
        "k":
            b"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
        "kty": "oct",
        "use": "sig"
    }]}


SESSION_INFO = {
    'sub': 'subject_id',
    'client_id': 'https://example.com/rp',
    'response_type': ['code'],
    'authzreq': '{}'
}


class TestToken(object):
    @pytest.fixture(autouse=True)
    def create_token(self):
        kb = KeyBundle(JWKS["keys"])
        kj = KeyJar()
        kj.issuer_keys[''] = [kb]

        self.access_token = JWTToken(
            'T', keyjar=kj, lt_pattern={'code': 3600, 'token': 900},
            iss='https://example.com/as', sign_alg='RS256')

    def test_create(self):
        sid = rndstr(32)
        session_info = SESSION_INFO

        _jwt = self.access_token(sid, sinfo=session_info, kid='sign1')

        assert _jwt
        assert len(_jwt.split('.')) == 3  # very simple JWS check

    def test_create_with_aud(self):
        sid = rndstr(32)
        session_info = SESSION_INFO

        _jwt = self.access_token(sid, sinfo=session_info, kid='sign1',
                                 aud=['https://example.com/rs'])

        assert _jwt


class TestToken2(object):
    @pytest.fixture(autouse=True)
    def create_token(self):
        kb = KeyBundle(JWKS["keys"])
        kj = KeyJar()
        kj.issuer_keys[''] = [kb]

        self.access_token = JWTToken(
            'T', keyjar=kj, iss='https://example.com/as', sign_alg='RS256')

    def test_create(self):
        sid = rndstr(32)
        session_info = SESSION_INFO

        _jwt = self.access_token(sid, sinfo=session_info, kid='sign1',
                                 lifetime=1200)

        assert _jwt
        assert len(_jwt.split('.')) == 3  # very simple JWS check

    def test_create_with_aud(self):
        sid = rndstr(32)
        session_info = SESSION_INFO

        _jwt = self.access_token(
            sid, sinfo=session_info, kid='sign1',
            aud=['https://example.com/rs'], lifetime=1200)

        assert _jwt

        info = self.access_token.get_info(_jwt)
        assert info['exp'] - info['iat'] == 1200


class TestEncToken(object):
    @pytest.fixture(autouse=True)
    def create_token(self):
        kb = KeyBundle(JWKS["keys"])
        kj = KeyJar()
        kj.issuer_keys[''] = [kb]

        self.access_token = JWTToken('T', keyjar=kj,
                                     lt_pattern={'code': 3600, 'token': 900},
                                     iss='https://example.com/as', encrypt=True)

    def test_enc_create(self):
        sid = rndstr(32)
        session_info = SESSION_INFO

        _jwe = self.access_token(sid, sinfo=session_info, kid='sign1')

        assert _jwe
        assert len(_jwe.split('.')) == 5  # very simple JWE check

    def test_parse_enc(self):
        sid = rndstr(32)
        session_info = SESSION_INFO

        _jwe = self.access_token(sid, sinfo=session_info, kid='sign1')
        _info = self.access_token.get_info(_jwe)
        assert _info


class TestSessionDB(object):
    @pytest.fixture(autouse=True)
    def create_sdb(self):
        kb = KeyBundle(JWKS["keys"])
        kj = KeyJar()
        kj.issuer_keys[''] = [kb]

        self.sdb = SessionDB(
            "https://example.com/",
            db=DictSessionBackend(),
            code_factory=DefaultToken(
                'supersecret', 'verybadpassword', typ='A', lifetime=600),
            token_factory=JWTToken('T', keyjar=kj,
                                   lt_pattern={'code': 3600, 'token': 900},
                                   iss='https://example.com/as',
                                   sign_alg='RS256'),
            refresh_token_factory=JWTToken(
                'R', keyjar=kj, lt_pattern={'': 24 * 3600},
                iss='https://example.com/as')
        )

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

        with pytest.raises(ExpiredToken):
            self.sdb.refresh_token(dict2["access_token"], AREQ['client_id'])

    def test_refresh_token_cleared_session(self):
        ae = AuthnEvent('uid', 'salt')
        sid = self.sdb.create_authz_session(ae, AREQ)
        self.sdb[sid]['sub'] = 'sub'
        grant = self.sdb[sid]['code']
        dict1 = self.sdb.upgrade_to_token(grant, issue_refresh=True)
        ac1 = dict1['access_token']

        rtoken = dict1['refresh_token']
        dict2 = self.sdb.refresh_token(rtoken, AREQ['client_id'])

        assert ac1 != dict2["access_token"]

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
        assert info["sub"] == \
            '179670cdee6375c48e577317b2abd7d5cd26a5cdb1cfb7ef84af3d703c71d013'

        self.sdb.do_sub(sid, "other_random_value",
                        sector_id='http://example.com',
                        subject_type="pairwise")
        info2 = self.sdb[sid]
        assert info2["sub"] == \
            'aaa50d80f8780cf1c4beb39e8e126556292f5091b9e39596424fefa2b99d9c53'

        self.sdb.do_sub(sid, "another_random_value",
                        sector_id='http://other.example.com',
                        subject_type="pairwise")

        info2 = self.sdb[sid]
        assert info2["sub"] == \
            '62fb630e29f0d41b88e049ac0ef49a9c3ac5418c029d6e4f5417df7e9443976b'
