import os
from urllib.parse import parse_qs

import pytest
from jwkest.jwk import SYMKey

from oic.oic.claims_provider import ClaimsClient
from oic.oic.claims_provider import ClaimsServer
from oic.oic.claims_provider import UserClaimsRequest
from oic.oic.claims_provider import UserClaimsResponse
from oic.oic.claims_provider import UserInfoClaimsRequest
from oic.oic.message import OpenIDSchema
from oic.utils.authn.client import verify_client
from oic.utils.claims import ClaimsMode
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.keyio import keybundle_from_local_file
from oic.utils.userinfo import UserInfo

__author__ = 'rohe0002'


def _eq(l1, l2):
    return set(l1) == set(l2)


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)


class TestClaimsClient(object):
    @pytest.fixture(autouse=True)
    def create_claims_client(self):
        self.cc = ClaimsClient(client_id="client_1")
        self.cc.client_secret = "hemlig"
        self.cc.userclaims_endpoint = "https://example.com/claims"

    def test_construct_UserClaimsRequest(self):
        req = self.cc.construct_UserClaimsRequest(request_args={"sub": "norah",
                                                                "claims_names": [
                                                                    "gender",
                                                                    "birthdate"]})

        assert isinstance(req, UserClaimsRequest)
        assert _eq(req.keys(), ['client_secret', 'claims_names', 'sub',
                                'client_id'])
        assert req["sub"] == "norah"
        assert req["client_id"] == "client_1"

    def test_request_info(self):
        request_args = {"sub": "norah", "claims_names": ["gender", "birthdate"]}

        uri, body, headers, ucr = self.cc.request_info(UserClaimsRequest,
                                                       method="POST",
                                                       request_args=request_args)
        assert uri == "https://example.com/claims"
        assert query_string_compare(body,
                                    "claims_names=gender+birthdate&sub=norah&client_id=client_1&client_secret=hemlig")


def user_info(oicsrv, userdb, sub, client_id="", user_info_claims=None):
    identity = userdb[sub]
    if user_info_claims:
        result = {}
        for key, restr in user_info_claims["claims"].items():
            try:
                result[key] = identity[key]
            except KeyError:
                if restr == {"essential": True}:
                    raise Exception("Missing property '%s'" % key)
    else:
        result = identity

    return OpenIDSchema(**result)


USERDB = {
    "diana": {
        "birthdate": "02/14/2012",
        "gender": "female"
    }
}


class TestUserClaimsResponse(object):
    def test_init(self):
        info = user_info(None, USERDB, "diana")

        keys = [SYMKey(key="hemlig")]
        cresp = UserClaimsResponse(jwt=info.to_jwt(key=keys, algorithm="HS256"),
                                   claims_names=list(info.keys()))

        assert _eq(list(cresp.keys()), ["jwt", "claims_names"])
        assert _eq(cresp["claims_names"], ['gender', 'birthdate'])
        assert "jwt" in cresp


class TestClaimsServer(object):
    USER2MODE = {"diana": "aggregate",
                 "upper": "distribute",
                 "babs": "aggregate"}
    CDB = {
        "client_1": {"client_secret": "hemlig"}
    }

    @pytest.fixture(autouse=True)
    def create_claims_server(self, keyjar, session_db):
        self.srv = ClaimsServer("pyoicserv", session_db,
                                TestClaimsServer.CDB,
                                UserInfo(USERDB), verify_client,
                                keyjar=keyjar,
                                dist_claims_mode=ClaimsMode(
                                    TestClaimsServer.USER2MODE))

    def test_claims_endpoint(self):
        cc = ClaimsClient(client_id="client_1")
        cc.client_secret = "hemlig"
        req = cc.construct_UserClaimsRequest(
            request_args={"sub": "diana",
                          "claims_names": ["gender", "birthdate"]})

        resp = self.srv.claims_endpoint(req.to_urlencoded(), "")

        ucr = UserClaimsResponse().deserialize(resp.message, "json")
        ucr.verify(keyjar=self.srv.keyjar)

        assert _eq(ucr["claims_names"], ["gender", "birthdate"])
        assert "jwt" in ucr

    def test_claims_info_endpoint(self):
        self.srv.info_store['access_token'] = {'sub': 'some_sub',
                                               'gender': 'neutral',
                                               'birthdate': 'someday',
                                               'claims_names': ['gender', 'birthdate']}
        req = UserInfoClaimsRequest(access_token='access_token')
        resp = self.srv.claims_info_endpoint(req.to_urlencoded(), "")

        ucr = UserClaimsResponse().deserialize(resp.message, "json")
        ucr.verify()
        assert _eq(ucr["claims_names"], ["gender", "birthdate"])

    @pytest.fixture(scope="session")
    def keyjar(self):
        symkey = KeyBundle(
            [{"kty": "oct", "key": "abcdefghijklmnop", "use": "ver"},
             {"kty": "oct", "key": "abcdefghijklmnop", "use": "sig"}])
        base_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "data/keys"))
        rsakey = keybundle_from_local_file(
            os.path.abspath(os.path.join(base_path, "rsa.key")), "rsa",
            ["ver", "sig"])
        keyjar = KeyJar()
        keyjar["client1"] = [symkey, rsakey]
        keyjar[""] = rsakey
        return keyjar
