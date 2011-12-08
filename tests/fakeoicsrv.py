#!/usr/bin/env python

__author__ = 'rohe0002'

import random
import string

from oic.utils.sdb import SessionDB
from oic.oic import Server
from oic.oic.message import *

from oic.oauth2.message import factory
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


class MyFakeOICServer(Server):
    def __init__(self, jwt_keys=None):
        Server.__init__(self)
        self.sdb = SessionDB()
        if jwt_keys is None:
            self.jwt_keys = {}
        else:
            self.jwt_keys = jwt_keys

        self.client = {}
        self.registration_expires_in = 3600

    #noinspection PyUnusedLocal
    def request(self, path, method, body, **kwargs):
        part = urlparse.urlparse(path)
        path = part[2]
        query = part[4]

        response = Response
        response.status = 500
        content = ""

        if path == "/authorization":
            assert method == "GET"
            response, content = self.authorization_endpoint(query)
        elif path == "/token":
            assert method == "POST"
            response, content = self.token_endpoint(body)
        elif path == "/userinfo":
            assert method == "POST"
            response, content = self.userinfo_endpoint(body)
        elif path == "/refresh_session":
            assert method == "GET"
            response, content = self.refresh_session_endpoint(query)
        elif path == "/check_session":
            assert method == "GET"
            response, content = self.check_session_endpoint(query)
        elif path == "/end_session":
            assert method == "GET"
            response, content = self.end_session_endpoint(query)
        elif path == "/registration":
            if method == "POST":
                response, content = self.registration_endpoint(body)

        return response, content

    def authorization_endpoint(self, query):
        req = self.parse_authorization_request(query=query,extended=True)
        sid = self.sdb.create_authz_session(user_id="user", areq=req)
        _info = self.sdb[sid]
        resp = AuthorizationResponse(state=req.state, code=_info["code"])
        location = "%s?%s" % (req.redirect_uri, resp.get_urlencoded())
        response= Response({"location":location})
        response.status = 302
        content= ""
        return response, content

    def token_endpoint(self, body):
        if "grant_type=refresh_token" in body:
            req = self.parse_refresh_token_request(body=body, extended=True)
            _info = self.sdb.refresh_token(req.refresh_token)
        elif "grant_type=authorization_code":
            req = self.parse_token_request(body=body, extended=True)
            _info = self.sdb.update_to_token(req.code)
        else:
            response = TokenErrorResponse("unsupported_grant_type")
            return response, ""
        
        resp = factory(AccessTokenResponse, **_info)
        content = resp.get_json()
        response = Response({"content-type":"application/json"})

        return response, content

    def userinfo_endpoint(self, body):

        _ = self.parse_user_info_request(body, extended=True)
        _info = {
            "name": "Melody Gardot",
            "nickname": "Mel",
            "email": "mel@example.com",
            "verified": True,
        }

        resp = factory(UserInfoResponse, **_info)
        content = resp.get_json()
        response = Response({"content-type":"application/json"})

        return response, content

    def registration_endpoint(self, body):
        req = self.parse_registration_request(body)

        client_secret = rndstr()
        if req.type == "client_associate":
            client_id = rndstr(10)

            self.client[client_id] = {
                "client_secret": client_secret,
                "info": req.dictionary(),
                "expires": time_sans_frac() + self.registration_expires_in
            }
        else:
            _cinfo = self.client[req.client_id]
            _cinfo["info"].update(req.directory())
            _cinfo["client_secret"] = client_secret
            _cinfo["expires"] = time_sans_frac() + self.registration_expires_in

        resp = RegistrationResponse(client_id=client_id,
                                    client_secret=client_secret,
                                    expires_in=self.registration_expires_in)

        response = Response({"content-type":"application/json"})
        return response, resp.get_json()

    def check_session_endpoint(self, query):
        try:
            idtoken = self.parse_check_session_request(query=query)
        except Exception:
            raise

        response = Response({"content-type":"application/json"})
        return response, idtoken.get_json()

    def refresh_session_endpoint(self, query):
        try:
            req = self.parse_refresh_session_request(query=query)
        except Exception:
            raise

        resp = RegistrationResponse(client_id="anonymous",
                                    client_secret="hemligt")
        response = Response({"content-type":"application/json"})
        return response, resp.get_json()

    def end_session_endpoint(self, query):
        try:
            req = self.parse_end_session_request(query=query)
        except Exception:
            raise

        # redirect back
        resp = EndSessionResponse(state=req.state)
        url = "%s?%s" % (req.redirect_url, resp.get_urlencoded())
        response = Response({"location":url})
        response.status = 302  # redirect
        return response, ""
