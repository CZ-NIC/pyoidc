import base64
import datetime
import hashlib
import hmac
import json
import random
import time
from unittest import TestCase

import pytest
from freezegun import freeze_time

from oic.oic.message import AuthorizationRequest
from oic.oic.message import OpenIDRequest
from oic.utils.sdb import AccessCodeUsed
from oic.utils.sdb import AuthnEvent
from oic.utils.sdb import Crypt
from oic.utils.sdb import DefaultToken
from oic.utils.sdb import DictSessionBackend
from oic.utils.sdb import ExpiredToken
from oic.utils.sdb import WrongTokenType
from oic.utils.sdb import create_session_db

__author__ = "rohe0002"

AREQ = AuthorizationRequest(
    response_type="code",
    client_id="client1",
    redirect_uri="http://example.com/authz",
    scope=["openid"],
    state="state000",
)

AREQN = AuthorizationRequest(
    response_type="code",
    client_id="client1",
    redirect_uri="http://example.com/authz",
    scope=["openid"],
    state="state000",
    nonce="something",
)

AREQO = AuthorizationRequest(
    response_type="code",
    client_id="client1",
    redirect_uri="http://example.com/authz",
    scope=["openid", "offlien_access"],
    prompt="consent",
    state="state000",
)

OIDR = OpenIDRequest(
    response_type="code",
    client_id="client1",
    redirect_uri="http://example.com/authz",
    scope=["openid"],
    state="state000",
)


def _eq(l1, l2):
    return set(l1) == set(l2)


class TestAuthnEvent(object):
    """Tests for AuthnEvent class."""

    def test_from_json(self):
        dic = {"uid": "uid", "salt": "salt", "authn_time": 1000, "valid_until": 1500}
        ae = AuthnEvent.from_json(json.dumps(dic))
        assert ae.uid == "uid"
        assert ae.salt == "salt"
        assert ae.authn_time == 1000
        assert ae.valid_until == 1500

    def test_to_json(self):
        ae = AuthnEvent("uid", "salt", authn_time=1000, valid_until=1500)
        json_repr = ae.to_json()
        assert json.loads(json_repr) == {
            "uid": "uid",
            "salt": "salt",
            "authn_time": 1000,
            "valid_until": 1500,
            "authn_info": None,
        }


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

        self.token(sid=sid, ttype="T")
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
        factory = DefaultToken("secret", "password", lifetime=60)
        token = factory(sid="abc", ttype="T")
        assert factory.is_expired(token) is False

    def test_expired_stale(self):
        initial_datetime = datetime.datetime(2018, 2, 5, 10, 0, 0, 0)
        final_datetime = datetime.datetime(2018, 2, 5, 10, 1, 0, 0)
        factory = DefaultToken("secret", "password", lifetime=2)
        with freeze_time(initial_datetime) as frozen:
            token = factory(sid="abc", ttype="T")
            frozen.move_to(final_datetime)
            assert factory.is_expired(token) is True

    def test_expired_when(self):
        factory = DefaultToken("secret", "password", lifetime=2)
        token = factory(sid="abc", ttype="T")
        when = time.time() + 5  # 5 seconds from now
        assert factory.is_expired(token, when=when) is True


class TestSessionBackend(TestCase):
    """Unittests for SessionBackend - using the DictSessionBackend."""

    def setUp(self):
        self.backend = DictSessionBackend()

    def test_setitem(self):
        self.backend["key"] = "value"
        self.assertEqual(self.backend.storage["key"], "value")
        self.backend["key"] = "new_value"
        self.assertEqual(self.backend.storage["key"], "new_value")

    def test_getitem(self):
        self.backend.storage = {"key": "value"}
        self.assertEqual(self.backend["key"], "value")
        with self.assertRaises(KeyError):
            self.backend["missing"]

    def test_delitem(self):
        self.backend.storage = {"key": "value"}
        del self.backend["key"]
        self.assertEqual(self.backend.storage, {})

    def test_contains(self):
        self.backend["key"] = "value"
        self.assertTrue("key" in self.backend)
        self.assertFalse("missing" in self.backend)

    def test_get_by_sub(self):
        self.backend.storage = {"session_id": {"sub": "my_sub"}}
        self.assertEqual(set(self.backend.get_by_sub("my_sub")), {"session_id"})
        self.assertEqual(set(self.backend.get_by_sub("missing")), set())

    def test_get_by_sub_multiple(self):
        self.backend.storage = {
            "session_id1": {"sub": "my_sub"},
            "session_id2": {"sub": "my_sub"},
        }
        self.assertEqual(
            set(self.backend.get_by_sub("my_sub")), {"session_id1", "session_id2"}
        )

    def test_get_by_uid(self):
        aevent = AuthnEvent("my_uid", "some_salt").to_json()
        self.backend.storage = {"session_id": {"authn_event": aevent}}
        self.assertEqual(set(self.backend.get_by_uid("my_uid")), {"session_id"})
        self.assertEqual(set(self.backend.get_by_uid("missing")), set())

    def test_get_by_uid_multiple(self):
        aevent1 = AuthnEvent("my_uid", "some_salt").to_json()
        aevent2 = AuthnEvent("my_uid", "some_salt").to_json()
        self.backend.storage = {
            "session_id1": {"authn_event": aevent1},
            "session_id2": {"authn_event": aevent2},
        }
        self.assertEqual(
            set(self.backend.get_by_uid("my_uid")), {"session_id1", "session_id2"}
        )

    def test_get_client_ids_for_uid(self):
        aevent = AuthnEvent("my_uid", "some_salt").to_json()
        self.backend.storage = {
            "session_id": {"authn_event": aevent, "client_id": "my_client"}
        }
        self.assertEqual(
            set(self.backend.get_client_ids_for_uid("my_uid")), {"my_client"}
        )
        self.assertEqual(set(self.backend.get_client_ids_for_uid("missing")), set())

    def test_get_client_ids_for_uid_multiple(self):
        aevent1 = AuthnEvent("my_uid", "some_salt").to_json()
        aevent2 = AuthnEvent("my_uid", "some_salt").to_json()
        self.backend.storage = {
            "session_id1": {"authn_event": aevent1, "client_id": "my_client"},
            "session_id2": {"authn_event": aevent2, "client_id": "my_other"},
        }
        self.assertEqual(
            set(self.backend.get_client_ids_for_uid("my_uid")),
            {"my_client", "my_other"},
        )

    def test_get_verified_logout(self):
        aevent1 = AuthnEvent("my_uid1", "some_salt").to_json()
        aevent2 = AuthnEvent("my_uid2", "some_salt").to_json()
        self.backend.storage = {
            "session_id": {
                "authn_event": aevent1,
                "verified_logout": "verification key",
            },
            "session_id2": {"authn_event": aevent2},
        }
        self.assertEqual(
            self.backend.get_verified_logout("my_uid1"), "verification key"
        )
        self.assertIsNone(self.backend.get_verified_logout("my_uid2"))
        self.assertIsNone(self.backend.get_verified_logout("missing"))

    def test_get_verified_logout_multiple(self):
        aevent1 = AuthnEvent("my_uid", "some_salt").to_json()
        aevent2 = AuthnEvent("my_uid", "some_salt").to_json()
        self.backend.storage = {
            "session_id1": {
                "authn_event": aevent1,
                "verified_logout": "verification key",
            },
            "session_id2": {
                "authn_event": aevent2,
                "verified_logout": "verification key",
            },
        }
        self.assertEqual(self.backend.get_verified_logout("my_uid"), "verification key")

    def test_get_token_ids(self):
        aevent = AuthnEvent("my_uid", "some_salt").to_json()
        self.backend.storage = {
            "session_id": {"authn_event": aevent, "id_token": "Id token"}
        }
        self.assertEqual(set(self.backend.get_token_ids("my_uid")), {"Id token"})
        self.assertEqual(set(self.backend.get_token_ids("missing")), set())

    def test_get_token_ids_multiple(self):
        aevent1 = AuthnEvent("my_uid", "some_salt").to_json()
        aevent2 = AuthnEvent("my_uid", "some_salt").to_json()
        self.backend.storage = {
            "session_id1": {"authn_event": aevent1, "id_token": "Id token 1"},
            "session_id2": {"authn_event": aevent2, "id_token": "Id token 2"},
        }
        self.assertEqual(
            set(self.backend.get_token_ids("my_uid")), {"Id token 1", "Id token 2"}
        )

    def test_is_revoke_uid_false(self):
        aevent = AuthnEvent("my_uid", "some_salt").to_json()
        self.backend.storage = {"session_id": {"authn_event": aevent, "revoked": False}}
        self.assertFalse(self.backend.is_revoke_uid("my_uid"))

    def test_is_revoke_uid_true(self):
        aevent = AuthnEvent("my_uid", "some_salt").to_json()
        self.backend.storage = {"session_id": {"authn_event": aevent, "revoked": True}}
        self.assertTrue(self.backend.is_revoke_uid("my_uid"))

    def test_is_revoke_uid_multiple(self):
        aevent1 = AuthnEvent("my_uid", "some_salt").to_json()
        aevent2 = AuthnEvent("my_uid", "some_salt").to_json()
        self.backend.storage = {
            "session_id1": {"authn_event": aevent1, "revoked": True},
            "session_id2": {"authn_event": aevent2, "revoked": False},
        }
        self.assertTrue(self.backend.is_revoke_uid("my_uid"))


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
        ae1 = AuthnEvent("uid", "salt")
        sid = self.sdb.create_authz_session(ae1, AREQ)
        self.sdb[sid]["sub"] = "sub"
        grant = self.sdb[sid]["code"]
        _dict = self.sdb.upgrade_to_token(grant)

        print(_dict.keys())
        assert _eq(
            list(_dict.keys()),
            [
                "authn_event",
                "code",
                "authzreq",
                "revoked",
                "access_token",
                "token_type",
                "state",
                "redirect_uri",
                "code_used",
                "client_id",
                "scope",
                "oauth_state",
                "access_token_scope",
                "sub",
                "response_type",
            ],
        )

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
        assert _eq(
            _dict.keys(),
            [
                "authn_event",
                "code",
                "authzreq",
                "revoked",
                "access_token",
                "response_type",
                "token_type",
                "state",
                "redirect_uri",
                "code_used",
                "client_id",
                "scope",
                "oauth_state",
                "access_token_scope",
                "refresh_token",
                "sub",
            ],
        )

        # can't update again
        with pytest.raises(AccessCodeUsed):
            self.sdb.upgrade_to_token(grant)
            self.sdb.upgrade_to_token(_dict["access_token"])

    def test_upgrade_to_token_with_id_token_and_oidreq(self):
        ae2 = AuthnEvent("another_user_id", "salt")
        sid = self.sdb.create_authz_session(ae2, AREQ)
        self.sdb[sid]["sub"] = "sub"
        grant = self.sdb[sid]["code"]

        _dict = self.sdb.upgrade_to_token(grant, id_token="id_token", oidreq=OIDR)
        print(_dict.keys())
        assert _eq(
            list(_dict.keys()),
            [
                "authn_event",
                "code",
                "authzreq",
                "revoked",
                "oidreq",
                "access_token",
                "id_token",
                "response_type",
                "token_type",
                "state",
                "redirect_uri",
                "code_used",
                "client_id",
                "scope",
                "oauth_state",
                "access_token_scope",
                "sub",
            ],
        )

        assert _dict["id_token"] == "id_token"
        assert isinstance(_dict["oidreq"], OpenIDRequest)

    def test_refresh_token(self):
        ae = AuthnEvent("uid", "salt")
        sid = self.sdb.create_authz_session(ae, AREQ)
        self.sdb[sid]["sub"] = "sub"
        grant = self.sdb[sid]["code"]

        dict1 = self.sdb.upgrade_to_token(grant, issue_refresh=True).copy()
        rtoken = dict1["refresh_token"]
        dict2 = self.sdb.refresh_token(rtoken, AREQ["client_id"])

        assert dict1["access_token"] != dict2["access_token"]

        with pytest.raises(WrongTokenType):
            self.sdb.refresh_token(dict2["access_token"], AREQ["client_id"])

    def test_refresh_token_cleared_session(self):
        ae = AuthnEvent("uid", "salt")
        sid = self.sdb.create_authz_session(ae, AREQ)
        self.sdb[sid]["sub"] = "sub"
        grant = self.sdb[sid]["code"]
        dict1 = self.sdb.upgrade_to_token(grant, issue_refresh=True)
        ac1 = dict1["access_token"]

        # Purge the SessionDB
        self.sdb._db = {}

        rtoken = dict1["refresh_token"]
        dict2 = self.sdb.refresh_token(rtoken, AREQ["client_id"])

        assert ac1 != dict2["access_token"]
        assert self.sdb.is_valid(dict2["access_token"])

    def test_is_valid(self):
        ae1 = AuthnEvent("uid", "salt")
        sid = self.sdb.create_authz_session(ae1, AREQ)
        self.sdb[sid]["sub"] = "sub"
        grant = self.sdb[sid]["code"]

        assert self.sdb.is_valid(grant)

        sinfo = self.sdb.upgrade_to_token(grant, issue_refresh=True)
        assert not self.sdb.is_valid(grant)
        access_token = sinfo["access_token"]
        assert self.sdb.access_token.valid(access_token)

        refresh_token = sinfo["refresh_token"]
        sinfo = self.sdb.refresh_token(refresh_token, AREQ["client_id"])
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
        self.sdb[sid]["sub"] = "sub"

        grant = self.sdb[sid]["code"]
        tokens = self.sdb.upgrade_to_token(grant, issue_refresh=True)
        access_token = tokens["access_token"]
        refresh_token = tokens["refresh_token"]

        assert self.sdb.is_valid(access_token)

        self.sdb.revoke_token(access_token)
        assert not self.sdb.is_valid(access_token)

        sinfo = self.sdb.refresh_token(refresh_token, AREQ["client_id"])
        access_token = sinfo["access_token"]
        assert self.sdb.is_valid(access_token)

        self.sdb.revoke_refresh_token(refresh_token)
        assert not self.sdb.is_valid(refresh_token)

        try:
            self.sdb.refresh_token(refresh_token, AREQ["client_id"])
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
        self.sdb[sid]["sub"] = "sub"

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
        assert (
            info["sub"]
            == "179670cdee6375c48e577317b2abd7d5cd26a5cdb1cfb7ef84af3d703c71d013"
        )

        self.sdb.do_sub(
            sid,
            "other_random_value",
            sector_id="http://example.com",
            subject_type="pairwise",
        )
        info2 = self.sdb[sid]
        assert (
            info2["sub"]
            == "aaa50d80f8780cf1c4beb39e8e126556292f5091b9e39596424fefa2b99d9c53"
        )

        self.sdb.do_sub(
            sid,
            "another_random_value",
            sector_id="http://other.example.com",
            subject_type="pairwise",
        )

        info2 = self.sdb[sid]
        assert (
            info2["sub"]
            == "62fb630e29f0d41b88e049ac0ef49a9c3ac5418c029d6e4f5417df7e9443976b"
        )

    def test_get_authentication_event_dict(self):
        self.sdb._db["123"] = {}
        self.sdb._db["123"]["authn_event"] = {
            "uid": "uid",
            "salt": "salt",
            "authn_time": 1000,
            "valid_until": 1500,
        }
        ae = self.sdb.get_authentication_event("123")
        assert ae.uid == "uid"
        assert ae.salt == "salt"
        assert ae.authn_time == 1000
        assert ae.valid_until == 1500

    def test_get_authentication_event_json(self):
        self.sdb._db["123"] = {}
        self.sdb._db["123"]["authn_event"] = json.dumps(
            {"uid": "uid", "salt": "salt", "authn_time": 1000, "valid_until": 1500}
        )
        ae = self.sdb.get_authentication_event("123")
        assert ae.uid == "uid"
        assert ae.salt == "salt"
        assert ae.authn_time == 1000
        assert ae.valid_until == 1500

    def test_get_sids_from_uid_distributed(self):
        db = DictSessionBackend()
        sdb1 = create_session_db("https://example.com/1", "secret", "password", db=db)
        sdb2 = create_session_db("https://example.com/2", "secret", "password", db=db)
        ae = AuthnEvent("sub", "salt", time_stamp=time.time())
        sid1 = sdb1.create_authz_session(ae, AREQ)
        sdb1.do_sub(sid1, "salt")
        sid2 = sdb2.create_authz_session(ae, AREQ)
        sdb2.do_sub(sid2, "salt")
        sdb1sids = sdb1.get_sids_from_uid("sub")
        sdb2sids = sdb2.get_sids_from_uid("sub")
        assert sdb1sids == sdb2sids

    def test_get_client_ids_for_uid(self):
        self.sdb._db["123"] = {
            "authn_event": json.dumps({"uid": "my_uid", "salt": "salt"}),
            "client_id": "my_client",
        }
        assert self.sdb.get_client_ids_for_uid("my_uid") == ["my_client"]

    def test_get_verify_logout(self):
        self.sdb._db["123"] = {
            "authn_event": json.dumps({"uid": "my_uid", "salt": "salt"}),
            "verified_logout": "something",
        }
        assert self.sdb.get_verify_logout("my_uid") == "something"

    def test_set_verify_logout(self):
        self.sdb._db["123"] = {
            "authn_event": json.dumps({"uid": "my_uid", "salt": "salt"})
        }
        self.sdb.set_verify_logout("my_uid")
        assert self.sdb.get_verify_logout("my_uid") is not None

    def test_set_verify_logout_multiple(self):
        self.sdb._db["123"] = {
            "authn_event": json.dumps({"uid": "my_uid", "salt": "salt"})
        }
        self.sdb._db["321"] = {
            "authn_event": json.dumps({"uid": "my_uid", "salt": "salt"})
        }
        self.sdb.set_verify_logout("my_uid")
        assert self.sdb.get_verify_logout("my_uid") is not None
        assert (
            self.sdb._db["123"]["verified_logout"]
            == self.sdb._db["321"]["verified_logout"]
        )

    def test_get_token_ids(self):
        self.sdb._db["123"] = {
            "authn_event": json.dumps({"uid": "my_uid", "salt": "salt"}),
            "id_token": "Id token",
        }
        assert set(self.sdb.get_token_ids("my_uid")) == {"Id token"}

    def test_get_is_revoke_uid(self):
        self.sdb._db["123"] = {
            "authn_event": json.dumps({"uid": "my_uid", "salt": "salt"}),
            "revoked": True,
        }
        assert self.sdb.is_revoke_uid("my_uid")

    def test_revoke_uid(self):
        self.sdb._db["123"] = {
            "authn_event": json.dumps({"uid": "my_uid", "salt": "salt"})
        }
        self.sdb.revoke_uid("my_uid")
        assert self.sdb.is_revoke_uid("my_uid")


class TestCrypt(object):
    @pytest.fixture(autouse=True)
    def create_crypt(self):
        self.crypt = Crypt("4-amino-1H-pyrimidine-2-one")

    def test_encrypt_decrypt(self):
        ctext = self.crypt.encrypt("Cytosine")
        plain = self.crypt.decrypt(ctext).decode("utf-8")
        assert plain == "Cytosine        "

        ctext = self.crypt.encrypt("cytidinetriphosp")
        plain = self.crypt.decrypt(ctext).decode("utf-8")

        assert plain == "cytidinetriphosp"

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
