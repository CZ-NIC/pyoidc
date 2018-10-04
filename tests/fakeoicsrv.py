#!/usr/bin/env python
from future.backports.urllib.parse import parse_qs
from future.backports.urllib.parse import urlparse

from jwkest import jws
from jwkest.jws import alg2keytype

from oic import rndstr
from oic.oauth2.message import by_schema
from oic.oic import Server
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthorizationResponse
from oic.oic.message import EndSessionResponse
from oic.oic.message import OpenIDSchema
from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import RegistrationResponse
from oic.oic.message import TokenErrorResponse
from oic.utils.sdb import AuthnEvent
from oic.utils.time_util import utc_time_sans_frac
from oic.utils.webfinger import WebFinger

__author__ = 'rohe0002'


class Response():
    def __init__(self, base=None):
        self.status_code = 200
        if base:
            for key, val in base.items():
                self.__setitem__(key, val)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, item):
        return getattr(self, item)


ENDPOINT = {
    "authorization_endpoint": "/authorization",
    "token_endpoint": "/token",
    "user_info_endpoint": "/userinfo",
    "check_session_endpoint": "/check_session",
    "refresh_session_endpoint": "/refresh_session",
    "end_session_endpoint": "/end_session",
    "registration_endpoint": "/registration",
    "discovery_endpoint": "/discovery",
    "register_endpoint": "/register"
}


class MyFakeOICServer(Server):
    def __init__(self, name="", session_db_factory=None):
        Server.__init__(self)
        self.sdb = session_db_factory(name)
        self.name = name
        self.client = {}
        self.registration_expires_in = 3600
        self.host = ""
        self.webfinger = WebFinger()
        self.userinfo_signed_response_alg = ""

    def http_request(self, path, method="GET", **kwargs):
        part = urlparse(path)
        path = part[2]
        query = part[4]
        self.host = "%s://%s" % (part.scheme, part.netloc)

        response = Response
        response.status_code = 500
        response.text = ""

        if path == ENDPOINT["authorization_endpoint"]:
            assert method == "GET"
            response = self.authorization_endpoint(query)
        elif path == ENDPOINT["token_endpoint"]:
            assert method == "POST"
            response = self.token_endpoint(kwargs["data"])
        elif path == ENDPOINT["user_info_endpoint"]:
            assert method == "POST"
            response = self.userinfo_endpoint(kwargs["data"])
        elif path == ENDPOINT["refresh_session_endpoint"]:
            assert method == "GET"
            response = self.refresh_session_endpoint(query)
        elif path == ENDPOINT["check_session_endpoint"]:
            assert method == "GET"
            response = self.check_session_endpoint(query)
        elif path == ENDPOINT["end_session_endpoint"]:
            assert method == "GET"
            response = self.end_session_endpoint(query)
        elif path == ENDPOINT["registration_endpoint"]:
            if method == "POST":
                response = self.registration_endpoint(kwargs["data"])
        elif path == "/.well-known/webfinger":
            assert method == "GET"
            qdict = parse_qs(query)
            response.status_code = 200
            response.text = self.webfinger.response(qdict["resource"][0],
                                                    "%s/" % self.name)
        elif path == "/.well-known/openid-configuration":
            assert method == "GET"
            response = self.openid_conf()

        return response

    def authorization_endpoint(self, query):
        req = self.parse_authorization_request(query=query)
        aevent = AuthnEvent("user", "salt", authn_info="acr")
        sid = self.sdb.create_authz_session(aevent, areq=req)
        self.sdb.do_sub(sid, "client_salt")
        _info = self.sdb[sid]

        if "code" in req["response_type"]:
            if "token" in req["response_type"]:
                grant = _info["code"]
                if 'offline_access' in _info['scope']:
                    _dict = self.sdb.upgrade_to_token(grant, issue_refresh=True)
                else:
                    _dict = self.sdb.upgrade_to_token(grant)
                _dict["oauth_state"] = "authz",

                _dict = by_schema(AuthorizationResponse(), **_dict)
                resp = AuthorizationResponse(**_dict)
            else:
                _state = req["state"]
                resp = AuthorizationResponse(state=_state,
                                             code=_info["code"])

        else:  # "implicit" in req.response_type:
            grant = _info["code"]
            params = AccessTokenResponse.c_param.keys()

            _dict = dict([(k, v) for k, v in
                          self.sdb.upgrade_to_token(grant).items() if k in
                          params])
            try:
                del _dict["refresh_token"]
            except KeyError:
                pass

            if "id_token" in req["response_type"]:
                _idt = self.make_id_token(_info, issuer=self.name,
                                          access_token=_dict["access_token"])
                alg = "RS256"
                ckey = self.keyjar.get_signing_key(alg2keytype(alg),
                                                   _info["client_id"])
                _dict["id_token"] = _idt.to_jwt(key=ckey, algorithm=alg)

            resp = AccessTokenResponse(**_dict)

        location = resp.request(req["redirect_uri"])
        response = Response()
        response.headers = {"location": location}
        response.status_code = 302
        response.text = ""
        return response

    def token_endpoint(self, data):
        if "grant_type=refresh_token" in data:
            req = self.parse_refresh_token_request(body=data)
            _info = self.sdb.refresh_token(req["refresh_token"], req['client_id'])
        elif "grant_type=authorization_code" in data:
            req = self.parse_token_request(body=data)
            if 'offline_access' in self.sdb[req['code']]['scope']:
                _info = self.sdb.upgrade_to_token(req["code"], issue_refresh=True)
            else:
                _info = self.sdb.upgrade_to_token(req["code"])
        else:
            response = TokenErrorResponse(error="unsupported_grant_type")
            return response, ""

        resp = AccessTokenResponse(**by_schema(AccessTokenResponse, **_info))
        response = Response()
        response.headers = {"content-type": "application/json"}
        response.text = resp.to_json()

        return response

    def userinfo_endpoint(self, data):

        self.parse_user_info_request(data)
        _info = {
            "sub": "melgar",
            "name": "Melody Gardot",
            "nickname": "Mel",
            "email": "mel@example.com",
            "verified": True,
        }

        resp = OpenIDSchema(**_info)
        response = Response()

        if self.userinfo_signed_response_alg:
            alg = self.userinfo_signed_response_alg
            response.headers = {"content-type": "application/jwt"}
            key = self.keyjar.get_signing_key(alg2keytype(alg), "", alg=alg)
            response.text = resp.to_jwt(key, alg)
        else:
            response.headers = {"content-type": "application/json"}
            response.text = resp.to_json()

        return response

    def registration_endpoint(self, data):
        try:
            req = self.parse_registration_request(data, "json")
        except ValueError:
            req = self.parse_registration_request(data)

        client_secret = rndstr()
        expires = utc_time_sans_frac() + self.registration_expires_in
        kwargs = {}
        if "client_id" not in req:
            client_id = rndstr(10)
            registration_access_token = rndstr(20)
            _client_info = req.to_dict()
            kwargs.update(_client_info)
            _client_info.update({
                "client_secret": client_secret,
                "info": req.to_dict(),
                "expires": expires,
                "registration_access_token": registration_access_token,
                "registration_client_uri": "register_endpoint"
            })
            self.client[client_id] = _client_info
            kwargs["registration_access_token"] = registration_access_token
            kwargs["registration_client_uri"] = "register_endpoint"
            try:
                del kwargs["operation"]
            except KeyError:
                pass
        else:
            client_id = req.client_id
            _cinfo = self.client[req.client_id]
            _cinfo["info"].update(req.to_dict())
            _cinfo["client_secret"] = client_secret
            _cinfo["expires"] = expires

        resp = RegistrationResponse(client_id=client_id,
                                    client_secret=client_secret,
                                    client_secret_expires_at=expires,
                                    **kwargs)

        response = Response()
        response.headers = {"content-type": "application/json"}
        response.text = resp.to_json()

        return response

    def check_session_endpoint(self, query):
        try:
            idtoken = self.parse_check_session_request(query=query)
        except Exception:
            raise

        response = Response()
        response.text = idtoken.to_json()
        response.headers = {"content-type": "application/json"}
        return response

    def refresh_session_endpoint(self, query):
        self.parse_refresh_session_request(query=query)

        resp = RegistrationResponse(client_id="anonymous",
                                    client_secret="hemligt")

        response = Response()
        response.headers = {"content-type": "application/json"}
        response.text = resp.to_json()
        return response

    def end_session_endpoint(self, query):
        try:
            req = self.parse_end_session_request(query=query)
        except Exception:
            raise

        # redirect back
        resp = EndSessionResponse(state=req["state"])

        url = resp.request(req["redirect_url"])

        response = Response()
        response.headers = {"location": url}
        response.status_code = 302  # redirect
        response.text = ""
        return response

    @staticmethod
    def add_credentials(user, passwd):
        pass

    def openid_conf(self):
        endpoint = {}
        for point, path in ENDPOINT.items():
            endpoint[point] = "%s%s" % (self.host, path)

        signing_algs = list(jws.SIGNER_ALGS.keys())
        resp = ProviderConfigurationResponse(
            issuer=self.name,
            scopes_supported=["openid", "profile", "email", "address"],
            identifiers_supported=["public", "PPID"],
            flows_supported=["code", "token", "code token", "id_token",
                             "code id_token", "token id_token"],
            subject_types_supported=["pairwise", "public"],
            response_types_supported=["code", "token", "id_token",
                                      "code token", "code id_token",
                                      "token id_token", "code token id_token"],
            jwks_uri="http://example.com/oidc/jwks",
            id_token_signing_alg_values_supported=signing_algs,
            grant_types_supported=["authorization_code", "implicit"],
            **endpoint)

        response = Response()
        response.headers = {"content-type": "application/json"}
        response.text = resp.to_json()
        return response
