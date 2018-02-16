from future.backports.urllib.parse import parse_qs
from future.backports.urllib.parse import urlparse

import json
import time

import pytest

from oic import rndstr
from oic.extension.client import Client
from oic.extension.message import TokenIntrospectionRequest
from oic.extension.message import TokenIntrospectionResponse
from oic.extension.message import TokenRevocationRequest
from oic.extension.provider import Provider
from oic.extension.token import JWTToken
from oic.oauth2.message import AccessTokenRequest
from oic.oauth2.message import AccessTokenResponse
from oic.oauth2.message import AuthorizationRequest
from oic.oauth2.message import AuthorizationResponse
from oic.oauth2.message import TokenErrorResponse
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authz import Implicit
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.sdb import DefaultToken
from oic.utils.sdb import SessionDB
from oic.utils.sdb import lv_pack
from oic.utils.sdb import lv_unpack

CLIENT_CONFIG = {
    "client_id": "client1",
    'config': {'issuer': 'https://example.com/as'}
}

CONSUMER_CONFIG = {
    "authz_page": "/authz",
    "flow_type": "code",
    "scope": [],
    "response_type": "code",
}

ISSUER = "https://connect-op.heroku.com"
SERVER_INFO = {
    "version": "3.0",
    "issuer": ISSUER,
    "authorization_endpoint": "http://localhost:8088/authorization",
    "token_endpoint": "http://localhost:8088/token",
    "flows_supported": ["code", "token", "code token"],
}

CDB = {
    "a1b2c3": {
        "password": "hemligt",
        "client_secret": "drickyoughurt",
        "redirect_uris": [("http://localhost:8087/authz", None)],
        'token_endpoint_auth_method': 'client_secret_post',
        'response_types': ['code', 'token']
    },
    "client1": {
        "client_secret": "hemlighet",
        "redirect_uris": [("http://localhost:8087/authz", None)],
        'token_endpoint_auth_method': 'client_secret_post',
        'response_types': ['code', 'token']
    }
}

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
        "n": "wl0DPln-EFLqr_Ftn6A87wEQAUVbpZsUTN2OCEsJV0nhlvmX3GUzyZx5UXdlM3Dz68PfUWCgfx67Il6sURqWVCnjnU-_gr3GeDyzedj-"
             "lZejnBx-lEy_3j6B98SbcDfkJF6saXnPd7_kgilJT1_g-EVI9ifFB1cxZXHCd2WBeRABSCprAlCglF-YmnUeeDs5K32z2ckVjadF9BG2"
             "7CO5UfNq0K8jI9Yj_coOhM9dRNrQ9UVZNdQVG-bAIDhB2y2o3ASGwqchHouIxv5YZNGS0SMJL5t0edh483q1tSWPqBw-ZeryLztOedBB"
             "zSuJk7QDmL1B6B7KKUIrlUYJmVsYzw",
        "p": "6MEg5Di_IFiPGKvMFRjyx2t7YAOQ4KfdIkU_Khny1t1eCG5O07omPe_jLU8I5fPaD5F5HhWExLNureHD4K6LB18JPE3VE8chQROiRSNP"
             "Zo1-faUvHu-Dy0pr7I-TS8pl_P3vop1KelIbGwXhzPIRKQMqCEKi3tLJt4R_MQ18Dx0",
        "q": "1cZVPpUbf4p5n4cMv_kERCPh3cieMs4aVojgh3feAiJiLwWWL9Pc43oJUekK44aWMnbs68Y4kqXtc52PMtBDzVp0Gjt0lCY3M7MYRVI4"
             "JhtknqvQynMKQ2nKs3VldvVfY2SxyUmnRyEolQUGRA7rRMUyPb4AXhSR7oroRrJD59s",
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


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_lv_pack_unpack():
    lst = ['foo', 'kaka', 'banan', 'jordgubb']
    s = lv_pack(*lst)
    r = lv_unpack(s)
    assert r == lst


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        return {"uid": self.user}, time.time()


AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add("UNDEFINED", DummyAuthn(None, "username"))
# dealing with authorization
AUTHZ = Implicit()


class TestProvider(object):
    @pytest.fixture(autouse=True)
    def create_provider(self):
        kb = KeyBundle(JWKS["keys"])
        kj = KeyJar()
        kj.issuer_keys[''] = [kb]

        _sdb = SessionDB(
            "https://example.com/",
            db={},
            code_factory=DefaultToken('supersecret', 'verybadpassword',
                                      typ='A', lifetime=600),
            token_factory=JWTToken('T', keyjar=kj,
                                   lt_pattern={'code': 3600, 'token': 900},
                                   iss='https://example.com/as',
                                   sign_alg='RS256'),
            refresh_token_factory=JWTToken(
                'R', keyjar=kj, lt_pattern={'': 24 * 3600},
                iss='https://example.com/as')
        )
        #  name, sdb, cdb, authn_broker, authz, client_authn,
        self.provider = Provider("as", _sdb, CDB, AUTHN_BROKER, AUTHZ,
                                 verify_client,
                                 baseurl='https://example.com/as')

    def test_authorization_endpoint_faulty_redirect_uri(self):
        bib = {"state": "id-6da9ca0cc23959f5f33e8becd9b08cae",
               # faulty redirect uri
               "redirect_uri": "http://localhost:8087/cb",
               "response_type": ["code"],
               "client_id": "a1b2c3"}

        arq = AuthorizationRequest(**bib)
        resp = self.provider.authorization_endpoint(request=arq.to_urlencoded())
        assert resp.status_code == 400
        msg = json.loads(resp.message)
        assert msg["error"] == "invalid_request"

    def test_authenticated(self):
        client = Client(**CLIENT_CONFIG)
        client.authorization_endpoint = 'https://example.com/as'

        sid = rndstr(8)
        args = {
            'redirect_uri': "http://localhost:8087/authz",
            "state": sid, "response_type": 'code'}

        url, body, ht_args, csi = client.request_info(
            AuthorizationRequest, 'GET', request_args=args)

        resp = self.provider.authorization_endpoint(urlparse(url).query)
        assert resp.status_code == 303
        resp = urlparse(resp.message).query
        aresp = client.parse_authz_response(resp)

        assert isinstance(aresp, AuthorizationResponse)
        assert _eq(aresp.keys(), ['state', 'code', 'client_id', 'iss'])
        assert _eq(client.grant[sid].keys(), ['tokens', 'code', 'exp_in',
                                              'seed', 'id_token',
                                              'grant_expiration_time'])

    def test_authenticated_token(self):
        client = Client(**CLIENT_CONFIG)
        client.authorization_endpoint = 'https://example.com/as'

        sid = rndstr(8)
        args = {'redirect_uri': "http://localhost:8087/authz", "state": sid,
                "response_type": 'token'}

        url, body, ht_args, csi = client.request_info(AuthorizationRequest,
                                                      'GET', request_args=args)

        QUERY_STRING = url.split("?")[1]
        resp = self.provider.authorization_endpoint(QUERY_STRING)
        auth_resp = parse_qs(urlparse(resp.message).fragment)

        assert "access_token" in auth_resp
        assert auth_resp["token_type"][0] == "Bearer"

    def test_token_endpoint(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.token_factory['code'](sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": authreq.to_json(),
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz",
            'response_type': ['code']
        }

        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant,
                                  redirect_uri="http://example.com/authz",
                                  client_id="client1",
                                  client_secret="hemlighet",
                                  grant_type='authorization_code')

        resp = self.provider.token_endpoint(request=areq.to_urlencoded())
        atr = AccessTokenResponse().deserialize(resp.message, "json")
        assert _eq(atr.keys(), ['access_token', 'token_type'])

    def test_token_endpoint_no_cache(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.token_factory['code'](sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": authreq.to_json(),
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz",
            'response_type': ['code']
        }

        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant,
                                  redirect_uri="http://example.com/authz",
                                  client_id="client1",
                                  client_secret="hemlighet",
                                  grant_type='authorization_code')

        resp = self.provider.token_endpoint(request=areq.to_urlencoded())
        assert resp.headers == [('Pragma', 'no-cache'), ('Cache-Control', 'no-store'),
                                ('Content-type', 'application/json')]

    def test_token_endpoint_unauth(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id="client1",
                                       response_type='code')

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.token_factory['code'](sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": authreq.to_json(),
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz",
            'response_type': ['code']
        }

        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant,
                                  redirect_uri="http://example.com/authz",
                                  client_id="client2",
                                  client_secret="hemlighet",
                                  grant_type='authorization_code')

        resp = self.provider.token_endpoint(request=areq.to_urlencoded())
        atr = TokenErrorResponse().deserialize(resp.message, "json")
        assert _eq(atr.keys(), ['error_description', 'error'])

    def test_token_introspection(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.token_factory['code'](sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": authreq.to_json(),
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz",
            'response_type': ['code']
        }

        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant,
                                  redirect_uri="http://example.com/authz",
                                  client_id="client1",
                                  client_secret="hemlighet",
                                  grant_type='authorization_code')

        resp = self.provider.token_endpoint(request=areq.to_urlencoded())
        atr = AccessTokenResponse().deserialize(resp.message, "json")
        req = TokenIntrospectionRequest(token=atr['access_token'],
                                        client_id="client1",
                                        client_secret="hemlighet",
                                        token_type_hint='access_token')
        resp = self.provider.introspection_endpoint(request=req.to_urlencoded())
        assert resp
        ti_resp = TokenIntrospectionResponse().deserialize(resp.message, 'json')
        assert ti_resp['active'] is True

    def test_token_revocation_and_introspection(self):
        authreq = AuthorizationRequest(state="state",
                                       redirect_uri="http://example.com/authz",
                                       client_id="client1")

        _sdb = self.provider.sdb
        sid = _sdb.access_token.key(user="sub", areq=authreq)
        access_grant = _sdb.token_factory['code'](sid=sid)
        _sdb[sid] = {
            "oauth_state": "authz",
            "sub": "sub",
            "authzreq": authreq.to_json(),
            "client_id": "client1",
            "code": access_grant,
            "code_used": False,
            "redirect_uri": "http://example.com/authz",
            'response_type': ['code']
        }

        # Construct Access token request
        areq = AccessTokenRequest(code=access_grant,
                                  redirect_uri="http://example.com/authz",
                                  client_id="client1",
                                  client_secret="hemlighet",
                                  grant_type='authorization_code')

        resp = self.provider.token_endpoint(request=areq.to_urlencoded())
        atr = AccessTokenResponse().deserialize(resp.message, "json")

        req = TokenRevocationRequest(token=atr['access_token'],
                                     client_id="client1",
                                     client_secret="hemlighet",
                                     token_type_hint='access_token')
        resp = self.provider.revocation_endpoint(request=req.to_urlencoded())
        assert resp.status_code == 200

        req = TokenIntrospectionRequest(token=atr['access_token'],
                                        client_id="client1",
                                        client_secret="hemlighet",
                                        token_type_hint='access_token')
        resp = self.provider.introspection_endpoint(request=req.to_urlencoded())
        assert resp
        ti_resp = TokenIntrospectionResponse().deserialize(resp.message, 'json')
        assert ti_resp['active'] is False
