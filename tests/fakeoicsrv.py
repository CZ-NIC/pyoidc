#!/usr/bin/env python
__author__ = 'rohe0002'

import urlparse

from oic.utils.sdb import SessionDB
from oic.utils.time_util import time_sans_frac
from oic.utils.time_util import utc_time_sans_frac

from oic.oic import Server
from oic.oic.message import SCHEMA

from oic.oauth2.message import  by_schema, message_from_schema
from oic.oauth2 import rndstr

class Response():
    def __init__(self, base=None):
        self.status = 200
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
    def __init__(self, jwt_keys=None, name=""):
        Server.__init__(self, jwt_keys)
        self.sdb = SessionDB()
        self.name = name
        self.client = {}
        self.registration_expires_in = 3600
        self.host = ""

    #noinspection PyUnusedLocal
    def request(self, path, method="GET", body=None, **kwargs):
        part = urlparse.urlparse(path)
        path = part[2]
        query = part[4]
        self.host = "%s://%s" % (part.scheme, part.netloc)

        response = Response
        response.status = 500
        content = ""

        if path == ENDPOINT["authorization_endpoint"]:
            assert method == "GET"
            response, content = self.authorization_endpoint(query)
        elif path == ENDPOINT["token_endpoint"]:
            assert method == "POST"
            response, content = self.token_endpoint(body)
        elif path == ENDPOINT["user_info_endpoint"]:
            assert method == "POST"
            response, content = self.userinfo_endpoint(body)
        elif path == ENDPOINT["refresh_session_endpoint"]:
            assert method == "GET"
            response, content = self.refresh_session_endpoint(query)
        elif path == ENDPOINT["check_session_endpoint"]:
            assert method == "GET"
            response, content = self.check_session_endpoint(query)
        elif path == ENDPOINT["end_session_endpoint"]:
            assert method == "GET"
            response, content = self.end_session_endpoint(query)
        elif path == ENDPOINT["registration_endpoint"]:
            if method == "POST":
                response, content = self.registration_endpoint(body)
        elif path == "/.well-known/simple-web-discovery":
            assert method == "GET"
            response, content = self.issuer(query)
        elif path == "/swd_server":
            assert method == "GET"
            response, content = self.swd_server(query)
        elif path == "/.well-known/openid-configuration"\
        or path == "/providerconf/.well-known/openid-configuration":
            assert method == "GET"
            response, content = self.openid_conf()

        return response, content

    def authorization_endpoint(self, query):
        req = self.parse_authorization_request(query=query)
        sid = self.sdb.create_authz_session(user_id="user", areq=req)
        _info = self.sdb[sid]

        if "code" in req["response_type"]:
            if "token" in req["response_type"]:
                grant = _info["code"]
                _dict = self.sdb.update_to_token(grant)
                _dict["oauth_state"]="authz",

                _dict = by_schema(SCHEMA["AuthorizationResponse"], **_dict)
                resp = message_from_schema(SCHEMA["AuthorizationResponse"],
                                           **_dict)
                #resp.code = grant
            else:
                resp = message_from_schema(SCHEMA["AuthorizationResponse"],
                                           state=req["state"],
                                           code=_info["code"])

        else: # "implicit" in req.response_type:
            grant = _info["code"]
            _dict = self.sdb.update_to_token(grant)
            resp = message_from_schema(SCHEMA["AccessTokenResponse"], **_dict)

        location = resp.request(req["redirect_uri"])
        response= Response({"location":location})
        response.status = 302
        content= ""
        return response, content

    def token_endpoint(self, body):
        if "grant_type=refresh_token" in body:
            req = self.parse_refresh_token_request(body=body)
            _info = self.sdb.refresh_token(req["refresh_token"])
        elif "grant_type=authorization_code":
            req = self.parse_token_request(body=body)
            _info = self.sdb.update_to_token(req["code"])
        else:
            response = message_from_schema(SCHEMA["TokenErrorResponse"],
                                           error="unsupported_grant_type")
            return response, ""

        resp = message_from_schema(SCHEMA["AccessTokenResponse"],
                                   **by_schema("AccessTokenResponse", **_info))
        content = resp.to_json()
        response = Response({"content-type":"application/json"})

        return response, content

    def userinfo_endpoint(self, body):

        _ = self.parse_user_info_request(body)
        _info = {
            "name": "Melody Gardot",
            "nickname": "Mel",
            "email": "mel@example.com",
            "verified": True,
            }

        resp = message_from_schema(SCHEMA["OpenIDSchema"], **_info)
        content = resp.to_json()
        response = Response({"content-type":"application/json"})

        return response, content

    def registration_endpoint(self, body):
        req = self.parse_registration_request(body)

        client_secret = rndstr()
        expires = utc_time_sans_frac() + self.registration_expires_in
        if req["type"] == "client_associate":
            client_id = rndstr(10)

            self.client[client_id] = {
                "client_secret": client_secret,
                "info": req.to_dict(),
                "expires": expires
            }
        else:
            client_id = req.client_id
            _cinfo = self.client[req.client_id]
            _cinfo["info"].update(req.to_dict())
            _cinfo["client_secret"] = client_secret
            _cinfo["expires"] = expires

        resp = message_from_schema(SCHEMA["RegistrationResponse"],
                                   client_id=client_id,
                                   client_secret=client_secret,
                                   expires_at=expires)

        response = Response({"content-type":"application/json"})
        return response, resp.to_json()

    def check_session_endpoint(self, query):
        try:
            idtoken = self.parse_check_session_request(query=query)
        except Exception:
            raise

        response = Response({"content-type":"application/json"})
        return response, idtoken.to_json()

    #noinspection PyUnusedLocal
    def refresh_session_endpoint(self, query):
        try:
            req = self.parse_refresh_session_request(query=query)
        except Exception:
            raise

        resp = message_from_schema(SCHEMA["RegistrationResponse"],
                                    client_id="anonymous",
                                    client_secret="hemligt")

        response = Response({"content-type":"application/json"})
        return response, resp.to_json()

    def end_session_endpoint(self, query):
        try:
            req = self.parse_end_session_request(query=query)
        except Exception:
            raise

        # redirect back
        resp = message_from_schema(SCHEMA["EndSessionResponse"],
                                   state=req["state"])

        url = resp.request(req["redirect_url"])

        response = Response({"location":url})
        response.status = 302  # redirect
        return response, ""

    #noinspection PyUnusedLocal
    def add_credentials(self, user, passwd):
        return

    def issuer(self, query):
        request = self.parse_issuer_request(query)
        if request["principal"] == "foo@example.com":
            resp = message_from_schema(SCHEMA["IssuerResponse"],
                                       locations="http://example.com/")
        elif request["principal"] == "bar@example.org":
            swd = message_from_schema(SCHEMA["SWDServiceRedirect"],
                                      location="https://example.net/swd_server")
            resp = message_from_schema(SCHEMA["IssuerResponse"],
                                       SWD_service_redirect=swd,
                                       expires=time_sans_frac() + 600)
        else:
            resp = None

        if resp is None:
            response = Response()
            response.status = 401
            return response, ""
        else:
            response = Response({"content-type":"application/json"})
            return response, resp.to_json()

    def swd_server(self, query):
        request = self.parse_issuer_request(query)
        if request["principal"] == "bar@example.org":
            resp = message_from_schema(SCHEMA["IssuerResponse"],
                                       locations="http://example.net/providerconf")
        else:
            resp = None

        if resp is None:
            response = Response()
            response.status = 401
            return response, ""
        else:
            response = Response({"content-type":"application/json"})
            return response, resp.to_json()

    def openid_conf(self):
        endpoint = {}
        for point, path in ENDPOINT.items():
            endpoint[point] = "%s%s" % (self.host, path)

        resp = message_from_schema(SCHEMA["ProviderConfigurationResponse"],
                                   issuer=self.name,
                                   scopes_supported=["openid", "profile",
                                                     "email", "address"],
                                   identifiers_supported=["public", "PPID"],
                                   flows_supported=["code", "token",
                                                    "code token", "id_token",
                                                    "code id_token",
                                                    "token id_token"],
                                   **endpoint)

        response = Response({"content-type":"application/json"})
        return response, resp.to_json()

