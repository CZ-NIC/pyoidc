__author__ = 'rohe0002'

#from oic import oauth2
from oic.oic.message import *

RESPONSE2ERROR = {
    AuthorizationResponse: [AuthorizationErrorResponse, TokenErrorResponse],
    AccessTokenResponse: [TokenErrorResponse]
}

REQUEST2ENDPOINT = {
    AuthorizationRequest: "authorization_endpoint",
    AccessTokenRequest: "token_endpoint",
    RefreshAccessTokenRequest: "token_endpoint",
}


#noinspection PyMethodOverriding
class Client(oauth2.Client):
    def __init__(self, client_id=None, cache=None, timeout=None,
                 proxy_info=None, follow_redirects=True,
                 disable_ssl_certificate_validation=False, key=None,
                 algorithm="HS256", client_secret="", client_timeout=0,
                 expires_in=0):

        if expires_in:
            client_timeout = time_sans_frac() + expires_in

        oauth2.Client.__init__(self, client_id, cache, timeout, proxy_info,
                       follow_redirects, disable_ssl_certificate_validation,
                       key, algorithm, client_secret, client_timeout)

        self.file_store = "./file/"
        self.file_uri = "http://localhost/"

        # OpenID connect specific endpoints
        self.user_info_endpoint = None
        self.check_session = None
        self.refresh_session=None
        self.end_session=None

        self.id_token=None
        self.log = None

        self.request2endpoint = REQUEST2ENDPOINT
        self.response2error = RESPONSE2ERROR

    def construct_AuthorizationRequest(self, cls=AuthorizationRequest,
                                       request_args=None, extra_args=None,
                                       **kwargs):

        return oauth2.Client.construct_AuthorizationRequest(self, cls,
                                                            request_args,
                                                            extra_args,
                                                            **kwargs)

    #noinspection PyUnusedLocal
    def construct_AccessTokenRequest(self, cls=AccessTokenRequest,
                                     request_args=None, extra_args=None,
                                     **kwargs):

        return oauth2.Client.construct_AccessTokenRequest(self, cls,
                                                          request_args,
                                                          extra_args, **kwargs)

    def construct_RefreshAccessTokenRequest(self,
                                            cls=RefreshAccessTokenRequest,
                                            request_args=None, extra_args=None,
                                            **kwargs):

        return oauth2.Client.construct_AccessTokenRequest(self, cls,
                                                          request_args,
                                                          extra_args, **kwargs)

    def construct_UserInfoRequest(self, cls=UserInfoRequest,
                                  request_args=None, extra_args=None, **kwargs):

        if request_args is None:
            request_args = {}

        token = self._get_token(**kwargs)
        if token is None:
            raise Exception("No valid token available")

        request_args["access_token"] = token.access_token

        return self.construct_request(cls, request_args, extra_args)

    #noinspection PyUnusedLocal
    def construct_RegistrationRequest(self, cls=RegistrationRequest,
                                      request_args=None, extra_args=None,
                                      **kwargs):

        return self.construct_request(cls, request_args, extra_args)

    #noinspection PyUnusedLocal
    def construct_RefreshSessionRequest(self, cls=RefreshSessionRequest,
                                        request_args=None, extra_args=None,
                                        **kwargs):

        return self.construct_request(cls, request_args, extra_args)

    def construct_CheckSessionRequest(self, cls=CheckSessionRequest,
                                        request_args=None, extra_args=None,
                                        **kwargs):
        if request_args is None:
            request_args = {}

        token = self._get_token(**kwargs)
        if token is None:
            raise Exception("No valid token available")

        try:
            request_args["id_token"] = token.id_token
        except ValueError:
            raise Exception("No id token available")


        return self.construct_request(cls, request_args, extra_args)

    def construct_CheckIDRequest(self, cls=CheckIDRequest, request_args=None,
                                 extra_args=None, **kwargs):
        if request_args is None:
            request_args = {}

        token = self._get_token(**kwargs)
        if token is None:
            raise Exception("No valid token available")

        try:
            request_args["id_token"] = token.id_token
        except ValueError:
            raise Exception("No id token available")


        return self.construct_request(cls, request_args, extra_args)

    def construct_EndSessionRequest(self, cls=EndSessionRequest,
                                    request_args=None, extra_args=None,
                                    **kwargs):
        if request_args is None:
            request_args = {}

        token = self._get_token(**kwargs)
        if token is None:
            raise Exception("No valid token available")

        try:
            request_args["id_token"] = token.id_token
        except ValueError:
            raise Exception("No id token available")


        return self.construct_request(cls, request_args, extra_args)

    def construct_OpenIDRequest(self, cls=OpenIDRequest, request_args=None,
                                extra_args=None, **kwargs):
        if request_args is None:
            request_args = {}

        token = self._get_token(**kwargs)
        if token is None:
            raise Exception("No valid token available")

        try:
            request_args["id_token"] = token.id_token
        except ValueError:
            raise Exception("No id token available")

        return self.construct_request(cls, request_args, extra_args)

    # ------------------------------------------------------------------------

    def do_authorization_request(self, cls=AuthorizationRequest,
                                 state="", return_format="", method="GET",
                                 request_args=None, extra_args=None,
                                 http_args=None, resp_cls=None):

        return oauth2.Client.do_authorization_request(self, cls, state,
                                                      return_format, method,
                                                      request_args,
                                                      extra_args, http_args,
                                                      resp_cls)


    def do_access_token_request(self, cls=AccessTokenRequest, scope="",
                                state="", return_format="json", method="POST",
                                request_args=None, extra_args=None,
                                http_args=None, resp_cls=AccessTokenResponse):

        return oauth2.Client.do_access_token_request(self, cls, scope, state,
                                                     return_format, method,
                                                     request_args, extra_args,
                                                     http_args, resp_cls)

    def do_access_token_refresh(self, cls=RefreshAccessTokenRequest,
                                state="", return_format="json", method="POST",
                                request_args=None, extra_args=None,
                                http_args=None, resp_cls=AccessTokenResponse,
                                **kwargs):

        return oauth2.Client.do_access_token_refresh(self, cls, state,
                                                     return_format, method,
                                                     request_args,
                                                     extra_args, http_args,
                                                     resp_cls, **kwargs)

    def do_user_info_request(self, cls=UserInfoRequest, state="",
                             return_format="json", method="POST",
                             request_args=None, extra_args=None,
                             http_args=None, resp_cls=UserInfoResponse,
                             **kwargs):

        token = self._get_token(state=state, **kwargs)
        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    token=token)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       return_format, extended=False,
                                       state=state, http_args=http_args)

    def do_registration_request(self, cls=RegistrationRequest, scope="",
                                state="", return_format="json", method="POST",
                                request_args=None, extra_args=None,
                                http_args=None, resp_cls=RegistrationResponse):

        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       return_format, extended=False,
                                       state=state, http_args=http_args)

    def do_check_session_request(self, cls=CheckSessionRequest, scope="",
                                 state="", return_format="json", method="POST",
                                 request_args=None, extra_args=None,
                                 http_args=None,
                                 resp_cls=RegistrationResponse):

        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       return_format, extended=False,
                                       state=state, http_args=http_args)

    def do_check_id_request(self, cls=CheckIDRequest, scope="",
                                 state="", return_format="json", method="POST",
                                 request_args=None, extra_args=None,
                                 http_args=None, resp_cls=None):

        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       return_format, extended=False,
                                       state=state, http_args=http_args)

    def do_end_session_request(self, cls=EndSessionRequest, scope="",
                                 state="", return_format="json", method="POST",
                                 request_args=None, extra_args=None,
                                 http_args=None, resp_cls=EndSessionResponse):

        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       return_format, extended=False,
                                       state=state, http_args=http_args)

    def do_open_id_request(self, cls=OpenIDRequest, scope="",
                                 state="", return_format="json", method="POST",
                                 request_args=None, extra_args=None,
                                 http_args=None,
                                 resp_cls=AuthorizationResponse):

        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       return_format, extended=False,
                                       state=state, http_args=http_args)

    def get_or_post(self, uri, method, req, **kwargs):
        if method == "GET":
            path = uri + '?' + req.get_urlencoded()
        elif method == "POST":
            path = uri
            kwargs["body"] = req.get_urlencoded()
            header_ext = {"content-type": "application/x-www-form-urlencoded"}
            if "headers" in kwargs.keys():
                kwargs["headers"].update(header_ext)
            else:
                kwargs["headers"] = header_ext
        else:
            raise Exception("Unsupported HTTP method: '%s'" % method)

        return path, kwargs

    def user_info_request(self, method="GET", scope="openid", **kwargs):
        uir = UserInfoRequest()
        if self.grant[scope].valid_token():
            uir.access_token = self.grant[scope].access_token
        else:
            # raise oauth2.OldAccessToken
            if self.log:
                self.log.info("do access token refresh")
            try:
                self.do_access_token_refresh()
                uir.access_token = self.grant[scope].access_token
            except Exception:
                raise

        uri = self._endpoint("user_info_endpoint", **kwargs)

        path, kwargs = self.get_or_post(uri, method, uir, **kwargs)

        h_args = dict([(k, v) for k,v in kwargs.items() if k in HTTP_ARGS])

        return path, method, h_args

    def do_user_info_request(self, method="GET", scope="openid", **kwargs):
        path, method, h_args = self.user_info_request(method, scope, **kwargs)

        try:
            response, content = self.http.request(path, method, **h_args)
        except oauth2.MissingRequiredAttribute:
            raise

        if response.status == 200:
            assert "application/json" in response["content-type"]
        elif response.status == 500:
            raise Exception("ERROR: Something went wrong: %s" % content)
        else:
            raise Exception("ERROR: Something went wrong [%s]" % response.status)

        return UserInfoResponse.set_json(txt=content, extended=True)


#noinspection PyMethodOverriding
class Server(oauth2.Server):
    def __init__(self, jwt_keys=None):
        oauth2.Server.__init__(self)

        self.jwt_keys = jwt_keys or {}

    def _parse_urlencoded(self, url=None, query=None):
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        return urlparse.parse_qs(query)

    def parse_authorization_request(self, rcls=AuthorizationRequest,
                                    url=None, query=None, extended=False):
        return oauth2.Server.parse_authorization_request(self, rcls, url,
                                                         query, extended)

    def parse_token_request(self, rcls=AccessTokenRequest, body=None):
        return oauth2.Server.parse_token_request(self, rcls, body)

    def parse_refresh_token_request(self, rcls=RefreshAccessTokenRequest,
                                    body=None):
        return oauth2.Server.parse_refresh_token_request(self, rcls, body)

    def parse_check_session_request(self, url=None, query=None):
        """

        """
        param = self._parse_urlencoded(url, query)
        assert "id_token" in param # ignore the rest
        # have to start decoding the jwt in order to find out which
        # key to verify the JWT signature with
        info = json.loads(jwt.decode(param["id_token"][0], verify=False))

        #print info

        # in there there should be information about the client_id
        # Use that to find the key and do the signature verify

        return IdToken.set_jwt(param["id_token"][0],
                               key=self.jwt_keys[info["iss"]])


    def parse_open_id_request(self, data, format="json", extended=False):
        if format == "json":
            oidr = OpenIDRequest.set_json(data, extended)
        elif format == "urlencoded":
            if '?' in data:
                parts = urlparse.urlparse(data)
                scheme, netloc, path, params, query, fragment = parts[:6]
            else:
                query = data
            oidr = OpenIDRequest.set_urlencoded(query, extended)
        else:
            raise Exception("Unknown package format: '%s'" %  format)

        assert oidr.verify()
        return oidr

    def parse_user_info_request(self, url=None, query=None, extended=False):
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        return UserInfoRequest.set_urlencoded(query, extended)

    def parse_refresh_session_request(self, url=None, query=None,
                                      extended=False):
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        return RefreshSessionRequest.set_urlencoded(query, extended)
