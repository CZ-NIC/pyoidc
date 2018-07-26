from oic import rndstr
from oic.extension.client import Client
from oic.extension.provider import Provider
from oic.extension.token import JWTToken
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import Implicit
from oic.utils.http_util import Response
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar

__author__ = 'roland'

SERVER_INFO = {
    "version": "3.0",
    "issuer": "https://connect-op.heroku.com",
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    "flows_supported": ["code", "token", "code token"],
}

CDB = {
    "a1b2c3": {
        "password": "hemligt",
        "client_secret": "drickyoughurt"
    },
    "client1": {
        "client_secret": "hemlighet",
        "redirect_uris": [("http://localhost:8087/authz", None)]
    }
}


def _eq(l1, l2):
    return set(l1) == set(l2)


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        return {"uid": self.user}


def test_pkce_create():
    _cli = Client(config={'code_challenge': {'method': 'S256', 'length': 64}})
    args, cv = _cli.add_code_challenge()
    assert args['code_challenge_method'] == 'S256'
    assert _eq(list(args.keys()), ['code_challenge_method', 'code_challenge'])


def test_pkce_verify_256(session_db_factory):
    _cli = Client(config={'code_challenge': {'method': 'S256', 'length': 64}})
    args, cv = _cli.add_code_challenge()

    authn_broker = AuthnBroker()
    authn_broker.add("UNDEFINED", DummyAuthn(None, "username"))
    _prov = Provider("as",
                     session_db_factory(SERVER_INFO["issuer"]), CDB,
                     authn_broker, Implicit(), verify_client)

    assert _prov.verify_code_challenge(cv, args['code_challenge']) is True
    assert _prov.verify_code_challenge(cv, args['code_challenge'], 'S256') is True
    resp = _prov.verify_code_challenge('XXX', args['code_challenge'])
    assert isinstance(resp, Response)
    assert resp.info()['status_code'] == 401


def test_pkce_verify_512(session_db_factory):
    _cli = Client(config={'code_challenge': {'method': 'S512', 'length': 96}})
    args, cv = _cli.add_code_challenge()

    authn_broker = AuthnBroker()
    authn_broker.add("UNDEFINED", DummyAuthn(None, "username"))
    _prov = Provider("as",
                     session_db_factory(SERVER_INFO["issuer"]), CDB,
                     authn_broker, Implicit(), verify_client)

    assert _prov.verify_code_challenge(cv, args['code_challenge'], 'S512') is True
    resp = _prov.verify_code_challenge('XXX', args['code_challenge'])
    assert isinstance(resp, Response)
    assert resp.info()['status_code'] == 401


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


def test_pkce_token():
    kb = KeyBundle(JWKS["keys"])
    kj = KeyJar()
    kj.issuer_keys[''] = [kb]
    constructor = JWTToken('A', keyjar=kj, lt_pattern={'': 900},
                           iss='https://example.com/as', sign_alg='RS256',
                           encrypt=True)

    sid = rndstr(32)
    session_info = {
        'sub': 'subject_id',
        'client_id': 'https://example.com/rp',
        'response_type': ['code'],
        'authzreq': '{}'
    }

    _cli = Client(config={'code_challenge': {'method': 'S512', 'length': 96}})
    args, cv = _cli.add_code_challenge()

    access_grant = constructor(
        sid, sinfo=session_info, kid='sign1',
        code_challenge=args['code_challenge'],
        code_challenge_method=args['code_challenge_method'])

    _info = constructor.get_info(access_grant)
    assert _info['code_challenge_method'] == args['code_challenge_method']
    assert _info['code_challenge'] == args['code_challenge']
