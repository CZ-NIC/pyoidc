#!/usr/bin/env python
from mako.runtime import UNDEFINED
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.claims import ClaimsMode
from oic.utils.sdb import SessionDB
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import AuthzHandling
from oic.utils.userinfo import UserInfo
from pinit import KEYJAR

__author__ = 'rohe0002'

import sys

from oic.oic.message import OpenIDSchema
from oic.utils.keyio import keybundle_from_local_file

from oic.oic.claims_provider import ClaimsClient
from oic.oic.claims_provider import UserClaimsResponse
from oic.oic.claims_provider import UserClaimsRequest
from oic.oic.claims_provider import ClaimsServer


#noinspection PyUnusedLocal
def user_info(oicsrv, userdb, sub, client_id="", user_info_claims=None):
    #print >> sys.stderr, "claims: %s" % user_info_claims
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


class LOG():
    def info(self, txt):
        print >> sys.stdout, "INFO: %s" % txt

    def error(self, txt):
        print >> sys.stdout, "ERROR: %s" % txt

    def debug(self, txt):
        print >> sys.stdout, "DEBUG: %s" % txt


#noinspection PyUnusedLocal
def start_response(status, headers=None):
    return

USERDB = {
    "diana": {
        "birthdate": "02/14/2012",
        "gender": "female"
    }
}

USERINFO = UserInfo(USERDB)

CDB = {
    "client_1": {"client_secret": "hemlig"}
}


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, **kwargs):
        return {"uid": self.user}

AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add(UNDEFINED, DummyAuthn(None, "username"))

# dealing with authorization
AUTHZ = AuthzHandling()
SYMKEY = "symmetric key used to encrypt cookie info"

USER2MODE = {"diana": "aggregate",
             "upper": "distribute",
             "babs": "aggregate"}

# ============================================================================


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_1():
    cc = ClaimsClient(client_id="client_1")
    cc.client_secret = "hemlig"

    req = cc.construct_UserClaimsRequest(request_args={"sub": "norah",
                                         "claims_names": ["gender",
                                                          "birthdate"]})

    print req
    assert req.type() == "UserClaimsRequest"
    assert _eq(req.keys(), ['client_secret', 'claims_names', 'sub',
                            'client_id'])
    assert req["sub"] == "norah"
    assert req["client_id"] == "client_1"


def test_c2():
    cc = ClaimsClient(client_id="client_1")
    cc.client_secret = "hemlig"
    cc.userclaims_endpoint = "https://example.com/claims"
    request = UserClaimsRequest
    method = "POST"
    request_args = {"sub": "norah", "claims_names": ["gender", "birthdate"]}

    cc.request_info(request, method=method, request_args=request_args)


def test_srv1():

    info = user_info(None, USERDB, "diana")

    keys = {"hmac": "hemlig"}
    cresp = UserClaimsResponse(jwt=info.to_jwt(key=keys),
                               claims_names=info.keys())

    print cresp
    assert _eq(cresp.keys(), ["jwt", "claims_names"])
    assert _eq(cresp["claims_names"], ['gender', 'birthdate'])
    assert "jwt" in cresp


def test_srv2():
    cc = ClaimsClient(client_id="client_1")
    cc.client_secret = "hemlig"

    req = cc.construct_UserClaimsRequest(
        request_args={"sub": "diana", "claims_names": ["gender", "birthdate"]})

    srv = ClaimsServer("pyoicserv", SessionDB(), CDB, USERINFO, verify_client,
                       keyjar=KEYJAR, dist_claims_mode=ClaimsMode(USER2MODE))

    srv.keyjar[""] = keybundle_from_local_file("rsa.key", "rsa", ["ver", "sig"])

    assert srv

    resp = srv.claims_endpoint(req.to_urlencoded(), "")

    print resp.message

    ucr = UserClaimsResponse().deserialize(resp.message, "json")
    ucr.verify(keyjar=srv.keyjar)

    print ucr
    assert _eq(ucr["claims_names"], ["gender", "birthdate"])
    assert "jwt" in ucr

if __name__ == "__main__":
    test_1()