#!/usr/bin/env python
from jwkest.jws import alg2keytype
from oic.oauth2.message import by_schema

__author__ = 'rohe0002'

import urlparse

from oic.utils.sdb import SessionDB
from oic.utils.time_util import time_sans_frac
from oic.utils.time_util import utc_time_sans_frac

from oic.oic import Server

from oic.oic.message import *
from oic.oauth2 import rndstr

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
    "authorization_endpoint":"/authorization",
    "token_endpoint":"/token",
    "user_info_endpoint":"/userinfo",
    "check_session_endpoint":"/check_session",
    "refresh_session_endpoint": "/refresh_session",
    "end_session_endpoint": "/end_session",
    "registration_endpoint": "/registration"
}

class MyFakeOICServer(Server):
    def __init__(self, name=""):
        Server.__init__(self)
        self.sdb = SessionDB()
        self.name = name
        self.client = {}
        self.registration_expires_in = 3600
        self.host = ""

    #noinspection PyUnusedLocal
    def http_request(self, path, method="GET", **kwargs):
        part = urlparse.urlparse(path)
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
        elif path == "/.well-known/simple-web-discovery":
            assert method == "GET"
            response = self.issuer(query)
        elif path == "/swd_server":
            assert method == "GET"
            response = self.swd_server(query)
        elif path == "/.well-known/openid-configuration"\
        or path == "/providerconf/.well-known/openid-configuration":
            assert method == "GET"
            response = self.openid_conf()

        return response

    def authorization_endpoint(self, query):
        req = self.parse_authorization_request(query=query)
        sid = self.sdb.create_authz_session(sub="user", areq=req)
        _info = self.sdb[sid]
        _info["sub"] = _info["local_sub"]

        if "code" in req["response_type"]:
            if "token" in req["response_type"]:
                grant = _info["code"]
                _dict = self.sdb.update_to_token(grant)
                _dict["oauth_state"]="authz",

                _dict = by_schema(AuthorizationResponse(), **_dict)
                resp = AuthorizationResponse(**_dict)
                #resp.code = grant
            else:
                resp = AuthorizationResponse(state=req["state"],
                                             code=_info["code"])

        else: # "implicit" in req.response_type:
            grant = _info["code"]
            params = AccessTokenResponse.c_param.keys()

            _dict = dict([(k,v) for k,
                        v in self.sdb.update_to_token(grant).items() if k in
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
        response= Response()
        response.headers = {"location":location}
        response.status_code = 302
        response.text = ""
        return response

    def token_endpoint(self, data):
        if "grant_type=refresh_token" in data:
            req = self.parse_refresh_token_request(body=data)
            _info = self.sdb.refresh_token(req["refresh_token"])
        elif "grant_type=authorization_code":
            req = self.parse_token_request(body=data)
            _info = self.sdb.update_to_token(req["code"])
        else:
            response = TokenErrorResponse(error="unsupported_grant_type")
            return response, ""

        resp = AccessTokenResponse(**by_schema(AccessTokenResponse, **_info))
        response = Response()
        response.headers = {"content-type":"application/json"}
        response.text = resp.to_json()

        return response

    def userinfo_endpoint(self, data):

        _ = self.parse_user_info_request(data)
        _info = {
            "name": "Melody Gardot",
            "nickname": "Mel",
            "email": "mel@example.com",
            "verified": True,
            }

        resp = OpenIDSchema(**_info)
        response = Response()
        response.headers = {"content-type":"application/json"}
        response.text = resp.to_json()

        return response

    def registration_endpoint(self, data):
        req = self.parse_registration_request(data)

        client_secret = rndstr()
        expires = utc_time_sans_frac() + self.registration_expires_in
        kwargs = {}
        if req["type"] == "client_associate":
            client_id = rndstr(10)
            registration_access_token = rndstr(20)
            self.client[client_id] = {
                "client_secret": client_secret,
                "info": req.to_dict(),
                "expires": expires,
                "registration_access_token": registration_access_token
            }
            kwargs["registration_access_token"] = registration_access_token
        else:
            client_id = req.client_id
            _cinfo = self.client[req.client_id]
            _cinfo["info"].update(req.to_dict())
            _cinfo["client_secret"] = client_secret
            _cinfo["expires"] = expires

        resp = RegistrationResponseCARS(client_id=client_id,
                            client_secret=client_secret,
                            expires_at=expires,
                            **kwargs)

        response = Response()
        response.headers = {"content-type":"application/json"}
        response.text = resp.to_json()

        return response

    def check_session_endpoint(self, query):
        try:
            idtoken = self.parse_check_session_request(query=query)
        except Exception:
            raise

        response = Response()
        response.text = idtoken.to_json()
        response.headers = {"content-type":"application/json"}
        return response

    #noinspection PyUnusedLocal
    def refresh_session_endpoint(self, query):
        try:
            req = self.parse_refresh_session_request(query=query)
        except Exception:
            raise

        resp = RegistrationResponseCARS(client_id="anonymous",
                                    client_secret="hemligt")

        response = Response()
        response.headers = {"content-type":"application/json"}
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
        response.headers= {"location":url}
        response.status_code = 302  # redirect
        response.text = ""
        return response

    #noinspection PyUnusedLocal
    def add_credentials(self, user, passwd):
        return

    def issuer(self, query):
        request = self.parse_issuer_request(query)
        if request["principal"] == "foo@example.com":
            resp = IssuerResponse(locations="http://example.com/")
        elif request["principal"] == "bar@example.org":
            swd = SWDServiceRedirect(location="https://example.net/swd_server")
            resp = IssuerResponse(SWD_service_redirect=swd,
                                  expires=time_sans_frac() + 600)
        else:
            resp = None

        if resp is None:
            response = Response()
            response.status = 401
            return response, ""
        else:
            response = Response()
            response.headers = {"content-type":"application/json"}
            response.text = resp.to_json()
            return response

    def swd_server(self, query):
        request = self.parse_issuer_request(query)
        if request["principal"] == "bar@example.org":
            resp = IssuerResponse(locations="http://example.net/providerconf")
        else:
            resp = None

        if resp is None:
            response = Response()
            response.status_code = 401
            response.text = ""
            return response
        else:
            response = Response()
            response.headers = {"content-type":"application/json"}
            response.text = resp.to_json()
            return response

    def openid_conf(self):
        endpoint = {}
        for point, path in ENDPOINT.items():
            endpoint[point] = "%s%s" % (self.host, path)

        resp = ProviderConfigurationResponse(
                                   issuer=self.name,
                                   scopes_supported=["openid", "profile",
                                                     "email", "address"],
                                   identifiers_supported=["public", "PPID"],
                                   flows_supported=["code", "token",
                                                    "code token", "id_token",
                                                    "code id_token",
                                                    "token id_token"],
                                   **endpoint)

        response = Response()
        response.headers = {"content-type":"application/json"}
        response.text = resp.to_json()
        return response

