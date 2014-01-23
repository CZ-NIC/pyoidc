#!/usr/bin/env python
__author__ = 'rohe0002'

import urlparse

from oic.utils.sdb import SessionDB
from oic.oauth2 import Server
from oic.oauth2.message import *

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
}

class MyFakeOAuth2Server(Server):
    def __init__(self, jwt_keys=None, name=""):
        Server.__init__(self, jwt_keys=jwt_keys)
        self.sdb = SessionDB()
        self.name = name
        self.client = {}
        self.registration_expires_in = 3600
        self.host = ""

    #noinspection PyUnusedLocal
    def http_request(self, url, method="GET", **kwargs):
        part = urlparse.urlparse(url)
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

        return response

    def authorization_endpoint(self, query):
        req = self.parse_authorization_request(query=query)
        sid = self.sdb.create_authz_session(user_id="user", areq=req)
        _info = self.sdb[sid]

        if "code" in req["response_type"]:
            if "token" in req["response_type"]:
                grant = _info["code"]
                _dict = self.sdb.upgrade_to_token(grant)
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
                                    v in self.sdb.upgrade_to_token(grant).items() if k in
                                                                                    params])
            try:
                del _dict["refresh_token"]
            except KeyError:
                pass

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


