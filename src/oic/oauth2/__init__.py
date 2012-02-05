#!/usr/bin/env python
#

__author__ = 'rohe0002'

import httplib2
import time
import inspect
import random
import string

from oic.utils import time_util

DEF_SIGN_ALG = "HS256"

from oic.oauth2.message import *

Version = "2.0"

HTTP_ARGS = ["headers", "redirections", "connection_type"]

DEFAULT_POST_CONTENT_TYPE = 'application/x-www-form-urlencoded'

REQUEST2ENDPOINT = {
    "AuthorizationRequest": "authorization_endpoint",
    "AccessTokenRequest": "token_endpoint",
#    ROPCAccessTokenRequest: "authorization_endpoint",
#    CCAccessTokenRequest: "authorization_endpoint",
    "RefreshAccessTokenRequest": "token_endpoint",
    "TokenRevocationRequest": "token_endpoint",
}

RESPONSE2ERROR = {
    AuthorizationResponse: [AuthorizationErrorResponse, TokenErrorResponse],
    AccessTokenResponse: [TokenErrorResponse]
}

ENDPOINTS = ["authorization_endpoint", "token_endpoint",
             "token_revocation_endpoint"]


def rndstr(size=16):
    """
    Returns a string of random ascii characters or digits

    :param size: The length of the string
    :return: string
    """
    _basech = string.ascii_letters + string.digits
    return "".join([random.choice(_basech) for _ in range(size)])

# -----------------------------------------------------------------------------
# Authentication Methods

#noinspection PyUnusedLocal
def client_secret_basic(cli, cis, request_args=None, http_args=None, **kwargs):
    cli.http.add_credentials(cli.client_id, http_args["password"])

    return http_args

#noinspection PyUnusedLocal
def client_secret_post(cli, cis, request_args=None, http_args=None, **kwargs):

    if request_args is None:
        request_args = {}

    if not cis.client_secret:
        try:
            cis.client_secret = http_args["client_secret"]
            del http_args["client_secret"]
        except (KeyError, TypeError):
            cis.client_secret = cli.client_secret

    cis.client_id = cli.client_id

    return http_args

#noinspection PyUnusedLocal
def bearer_header(cli, cis, request_args=None, http_args=None, **kwargs):
    if cis.access_token:
        _acc_token = cis.access_token
        cis.access_token = None
        # Required under certain circumstances :-) not under other
        cis.c_attributes["access_token"] = SINGLE_OPTIONAL_STRING
    else:
        try:
            _acc_token = request_args["access_token"]
            del request_args["access_token"]
        except KeyError:
            try:
                _state = kwargs["state"]
            except KeyError:
                if not cli.state:
                    raise Exception("Missing state specification")
                kwargs["state"] = cli.state

            _acc_token= cli.get_token(**kwargs).access_token

    # Do I need to base64 encode the access token ? Probably !
    #_bearer = "Bearer %s" % base64.b64encode(_acc_token)
    _bearer = "Bearer %s" % _acc_token
    if http_args is None:
        http_args = {"headers": {}}
        http_args["headers"]["Authorization"] = _bearer
    else:
        try:
            http_args["headers"]["Authorization"] = _bearer
        except KeyError:
            http_args["headers"] = {"Authorization": _bearer}

    return http_args

#noinspection PyUnusedLocal
def bearer_body(cli, cis, request_args=None, http_args=None, **kwargs):
    if request_args is None:
        request_args = {}

    if cis.access_token:
        pass
    else:
        try:
            cis.access_token = request_args["access_token"]
        except KeyError:
            try:
                _state = kwargs["state"]
            except KeyError:
                if not cli.state:
                    raise Exception("Missing state specification")
                kwargs["state"] = cli.state

            cis.access_token = cli.get_token(**kwargs).access_token

    return http_args

AUTHN_METHOD = {
    "client_secret_basic": client_secret_basic,
    "client_secret_post" : client_secret_post,
    "bearer_header": bearer_header,
    "bearer_body": bearer_body,
}

# -----------------------------------------------------------------------------

class ExpiredToken(Exception):
    pass

# -----------------------------------------------------------------------------

class Token(object):
    _class = AccessTokenResponse

    def __init__(self, resp=None):
        self.scope = []
        self.token_expiration_time = 0
        self.access_token = None
        self.refresh_token = None
        self.token_type = None
        self.replaced = False

        if resp:
            for prop in self._class.c_attributes.keys():
                try:
                    _val = getattr(resp, prop)
                except KeyError:
                    continue
                if _val:
                    setattr(self, prop, _val)

            for key, val in resp.c_extension.items():
                setattr(self, key, val)

            try:
                _expires_in = resp.expires_in
            except KeyError:
                return

            if _expires_in:
                _tet = time_util.time_sans_frac() + int(_expires_in)
            else:
                _tet = 0
            self.token_expiration_time = int(_tet)


    def is_valid(self):
        if self.token_expiration_time:
            if time.time() > self.token_expiration_time:
                return False

        return True

    def __str__(self):
        return "%s" % self.__dict__

    def keys(self):
        return self.__dict__.keys()

    def __eq__(self, other):
        skeys = self.keys()
        okeys = other.keys()
        if set(skeys) != set(okeys):
            return False

        for key in skeys:
            if getattr(self, key) != getattr(other, key):
                return False

        return True

class Grant(object):
    _authz_resp = AuthorizationResponse
    _acc_resp = AccessTokenResponse
    _token_class = Token
    
    def __init__(self, exp_in=600, resp=None, seed=""):
        self.grant_expiration_time = 0
        self.exp_in = exp_in
        self.seed = seed
        self.tokens = []
        self.id_token = None
        if resp:
            self.add_code(resp)
            self.add_token(resp)

    @classmethod
    def from_code(cls, resp):
        instance = cls()
        instance.add_code(resp)
        return instance

    def add_code(self, resp):
        try:
            self.code = resp.code
            self.grant_expiration_time = time_util.time_sans_frac() + self.exp_in
        except KeyError:
            pass

    def add_token(self, resp):
        tok = self._token_class(resp)
        if tok.access_token:
            self.tokens.append(tok)

    def is_valid(self):
        if time.time() > self.grant_expiration_time:
            return False
        else:
            return True

    def __str__(self):
        return "%s" % self.__dict__

    def keys(self):
        return self.__dict__.keys()

    def update(self, resp):
        if isinstance(resp, self._acc_resp):
            tok = self._token_class(resp)
            if tok not in self.tokens:
                for otok in self.tokens:
                    if tok.scope == otok.scope:
                        otok.replaced = True
                self.tokens.append(tok)
        elif isinstance(resp, self._authz_resp):
            self.add_code(resp)

    def get_token(self, scope=""):
        token = None
        if scope:
            for token in self.tokens:
                if scope in token.scope and not token.replaced:
                    return token
        else:
            for token in self.tokens:
                if token.is_valid() and not token.replaced:
                    return token

        return token

    def get_id_token(self):
        return self.id_token

    def join(self, grant):
        if not self.exp_in:
            self.exp_in = grant.exp_in
        if not self.grant_expiration_time:
            self.grant_expiration_time = grant.grant_expiration_time
        if not self.seed:
            self.seed = grant.seed
        for token in grant.tokens:
            if token not in self.tokens:
                for otok in self.tokens:
                    if token.scope == otok.scope:
                        otok.replaced = True
                self.tokens.append(token)

        
class Client(object):
    _endpoints = ENDPOINTS

    def __init__(self, client_id=None, cache=None, time_out=None,
                 proxy_info=None, follow_redirects=True,
                 disable_ssl_certificate_validation=False,
                 ca_certs="", #jwt_key=None,
                 grant_expire_in=600, client_secret="", client_timeout=0,
                 httpclass=None):

        self._c_secret = None
        self.send_keys = {"sign": {}, "verify": {}, "enc": {}, "dec": {}}
        self.recv_keys = {"sign": {}, "verify": {}, "enc": {}, "dec": {}}

        if not ca_certs and disable_ssl_certificate_validation is False:
            disable_ssl_certificate_validation = True

        if httpclass is None:
            httpclass = httplib2.Http

        self.http = httpclass(cache=cache, timeout=time_out,
            proxy_info=proxy_info, ca_certs=ca_certs,
            disable_ssl_certificate_validation=disable_ssl_certificate_validation)
        self.http.follow_redirects = follow_redirects

        self.client_id = client_id
        self.client_secret = client_secret
        self.client_timeout = client_timeout
        #self.secret_type = "basic "

        self.state = None
        self.nonce = None

        self.grant_expire_in = grant_expire_in
        self.grant = {}

        # own endpoint
        self.redirect_uri = None

        # service endpoints
        self.authorization_endpoint=None
        self.token_endpoint=None
        self.token_revocation_endpoint=None

        self.request2endpoint = REQUEST2ENDPOINT
        self.response2error = RESPONSE2ERROR
        self.authn_method = AUTHN_METHOD
        self.grant_class = Grant
        self.token_class = Token

    def get_client_secret(self):
        return self._c_secret

    def set_client_secret(self, val):
        self._c_secret = val
        # client uses it for signing
        self.send_keys["sign"]["hmac"] = val
        # Server might also use it for signing which means the
        # client uses it for verifying server signatures
        self.recv_keys["verify"]["hmac"] = val

    client_secret = property(get_client_secret, set_client_secret)

    def get_verify_key(self):
        return self.recv_keys["verify"]

    def set_verify_key(self, val):
        if isinstance(val, tuple):
            self.recv_keys["verify"][val[0]] = val[1]
        elif isinstance(val, dict):
            self.recv_keys["verify"].update(val)
        else: # assume hmac key
            self.recv_keys["verify"]["hmac"] = val

    verify_key = property(get_verify_key, set_verify_key)

    def get_decrypt_key(self):
        return self.recv_keys["dec"]

    def set_decrypt_key(self, val):
        if isinstance(val, tuple):
            self.recv_keys["dec"][val[0]] = val[1]
        elif isinstance(val, dict):
            self.recv_keys["dec"].update(val)
        else: # assume hmac key
            self.recv_keys["dec"]["hmac"] = val

    decrypt_key = property(get_decrypt_key, set_decrypt_key)

    def reset(self):
        self.state = None
        self.nonce = None

        self.grant = {}

        self.authorization_endpoint=None
        self.token_endpoint=None
        self.redirect_uri = None

    def grant_from_state(self, state):
        for key, grant in self.grant.items():
            if key == state:
                return grant

        return None

#    def scope_from_state(self, state):
#
#    def grant_from_state_or_scope(self, state, scope):

    def _parse_args(self, klass, **kwargs):
        ar_args = {}
        for prop, val in kwargs.items():
            if prop in klass.c_attributes:
                ar_args[prop] = val
            elif prop.startswith("extra_"):
                if prop[6:] not in klass.c_attributes:
                    ar_args[prop[6:]] = val

        # Used to not overwrite defaults
        argspec = inspect.getargspec(klass.__init__)
        for prop in klass.c_attributes.keys():
            if prop not in ar_args:
                index = argspec[0].index(prop) -1 # skip self
                if not argspec[3][index]:
                    ar_args[prop] = getattr(self, prop, None)

        return ar_args

    def _endpoint(self, endpoint, **kwargs):
        try:
            uri = kwargs[endpoint]
            if uri:
                del kwargs[endpoint]
        except KeyError:
            uri = ""

        if not uri:
            try:
                uri = getattr(self, endpoint)
            except Exception:
                raise Exception("No '%s' specified" % endpoint)

        if not uri:
            raise Exception("No '%s' specified" % endpoint)

        return uri

    def get_grant(self, **kwargs):
        try:
            _state = kwargs["state"]
            if not _state:
                _state = self.state
        except KeyError:
            _state = self.state

        try:
            return self.grant[_state]
        except:
            raise Exception("No grant found for state:'%s'" % _state)

    def get_token(self, also_expired=False, **kwargs):
        try:
            return kwargs["token"]
        except KeyError:
            grant = self.get_grant(**kwargs)

            try:
                token = grant.get_token(kwargs["scope"])
            except KeyError:
                token = grant.get_token("")
                if not token:
                    try:
                        token = self.grant[kwargs["state"]].get_token("")
                    except KeyError:
                        raise Exception("No token found for scope")

        if token is None:
            raise Exception("No suitable token found")

        if also_expired:
            return token
        elif token.is_valid():
            return token
        else:
            raise ExpiredToken()

    def construct_request(self, reqclass, request_args=None, extra_args=None):
        if request_args is None:
            request_args = {}

        args = self._parse_args(reqclass, **request_args)

        if extra_args:
            args.update(extra_args)
        return reqclass(**args)

    #noinspection PyUnusedLocal
    def construct_AuthorizationRequest(self, reqclass=AuthorizationRequest,
                                       request_args=None, extra_args=None,
                                       **kwargs):

        if request_args is not None:
            try: # change default
                self.redirect_uri = request_args["redirect_uri"]
            except KeyError:
                pass
        else:
            request_args = {}

        return self.construct_request(reqclass, request_args, extra_args)

    #noinspection PyUnusedLocal
    def construct_AccessTokenRequest(self, cls=AccessTokenRequest,
                                     request_args=None, extra_args=None,
                                     **kwargs):

        grant = self.get_grant(**kwargs)

        if not grant.is_valid():
            raise GrantExpired("Authorization Code to old %s > %s" % (time.time(),
                                                grant.grant_expiration_time))

        if request_args is None:
            request_args = {}

        request_args["code"] = grant.code

        if "grant_type" not in request_args:
            request_args["grant_type"] = "authorization_code"

        if "client_id" not in request_args:
            request_args["client_id"] = self.client_id
        elif not request_args["client_id"]:
            request_args["client_id"] = self.client_id

        return self.construct_request(cls, request_args, extra_args)

    def construct_RefreshAccessTokenRequest(self,
                                            cls=RefreshAccessTokenRequest,
                                            request_args=None, extra_args=None,
                                            **kwargs):

        if request_args is None:
            request_args = {}

        token = self.get_token(also_expired=True, **kwargs)

        request_args["refresh_token"] = token.refresh_token

        try:
            request_args["scope"] = token.scope
        except AttributeError:
            pass

        return self.construct_request(cls, request_args, extra_args)

    def construct_TokenRevocationRequest(self, cls=TokenRevocationRequest,
                                         request_args=None, extra_args=None,
                                         **kwargs):

        if request_args is None:
            request_args = {}

        token = self.get_token(**kwargs)

        request_args["token"] = token.access_token
        return self.construct_request(cls, request_args, extra_args)

    def get_or_post(self, uri, method, req, extend=False, **kwargs):
        if method == "GET":
            path = uri + '?' + req.get_urlencoded(extended=extend)
            body = None
        elif method == "POST":
            path = uri
            body = req.get_urlencoded(extended=extend)
            header_ext = {"content-type": DEFAULT_POST_CONTENT_TYPE}
            if "headers" in kwargs.keys():
                kwargs["headers"].update(header_ext)
            else:
                kwargs["headers"] = header_ext
        else:
            raise Exception("Unsupported HTTP method: '%s'" % method)

        return path, body, kwargs

    def uri_and_body(self, cls, cis, method="POST", request_args=None,
                     extend=False, **kwargs):

        uri = self._endpoint(self.request2endpoint[cls.__name__],
                             **request_args)

        uri, body, kwargs = self.get_or_post(uri, method, cis, extend, **kwargs)
        try:
            h_args = {"headers": kwargs["headers"]}
        except KeyError:
            h_args = {}

        return uri, body, h_args, cis

    def request_info(self, cls, method="POST", request_args=None,
                     extra_args=None, **kwargs):

        if request_args is None:
            request_args = {}

        cis = getattr(self, "construct_%s" % cls.__name__)(cls, request_args,
                                                           extra_args,
                                                           **kwargs)

        if "authn_method" in kwargs:
            h_arg = self.init_authentication_method(cis,
                                                    request_args=request_args,
                                                    **kwargs)
        else:
            h_arg = None

        if h_arg:
            if "headers" in kwargs.keys():
                kwargs["headers"].update(h_arg)
            else:
                kwargs["headers"] = h_arg

        if extra_args:
            extend = True
        else:
            extend = False

        return self.uri_and_body(cls, cis, method, request_args,
                                 extend=extend, **kwargs)

    def parse_response(self, cls, info="", format="json", state="",
                       extended=False, **kwargs):
        """
        Parse a response

        :param cls: Which class to use when parsing the response
        :param info: The response, can be either an JSON code or an urlencoded
            form:
        :param format: Which serialization that was used
        :param extended: If non-standard parameters should be honored
        :return: The parsed and to some extend verified response
        """

        _r2e = self.response2error

        err = None
        if format == "json":
            try:
                resp = cls.set_json(info, extended)
                assert resp.verify(**kwargs)
            except Exception, err:
                resp = None

            eresp = None
            for errcls in _r2e[cls]:
                try:
                    eresp = errcls.set_json(info, extended)
                    eresp.verify()
                    break
                except Exception:
                    eresp = None

        elif format == "urlencoded":
            if '?' in info or '#' in info:
                parts = urlparse.urlparse(info)
                scheme, netloc, path, params, query, fragment = parts[:6]
                # either query of fragment
                if query:
                    pass
                else:
                    query = fragment
            else:
                query = info

            try:
                resp = cls.set_urlencoded(query, extended)
                assert resp.verify(**kwargs)
            except Exception, err:
                resp = None

            eresp = None
            for errcls in _r2e[cls]:
                try:
                    eresp = errcls.set_urlencoded(query, extended)
                    eresp.verify()
                    break
                except Exception:
                    eresp = None

        else:
            raise Exception("Unknown package format: '%s'" %  format)

        # Error responses has higher precedence
        if eresp:
            resp = eresp

        if not resp:
            raise err

        if not isinstance(resp, ErrorResponse):
            try:
                _state = resp.state
            except (AttributeError, KeyError):
                _state = ""

            if not _state:
                _state = state

            try:
                self.grant[_state].update(resp)
            except KeyError:
                self.grant[_state] = self.grant_class(resp=resp)

        return resp

    #noinspection PyUnusedLocal
    def init_authentication_method(self, cis, authn_method, request_args=None,
                                     http_args=None, **kwargs):

        if http_args is None:
            http_args = {}
        if request_args is None:
            request_args = {}

        if authn_method:
            return self.authn_method[authn_method](self, cis, request_args,
                                                   http_args)
        else:
            return http_args

    def request_and_return(self, url, respcls=None, method="GET", body=None,
                        body_type="json", extended=True,
                        state="", http_args=None):
        """
        :param url: The URL to which the request should be sent
        :param respcls: The class the should represent the response
        :param method: Which HTTP method to use
        :param body: A message body if any
        :param body_type: The format of the body of the return message
        :param extended: If non-standard parameters should be honored
        :param http_args: Arguments for the HTTP client
        :return: A cls or ErrorResponse instance or the HTTP response
            instance if no response body was expected.
        """

        if http_args is None:
            http_args = {}

        try:
            response, content = self.http.request(url, method, body=body,
                                                  **http_args)
        except Exception:
            raise

        if response.status == 200:
            if body_type == "":
                pass
            elif body_type == "json":
                assert "application/json" in response["content-type"]
            elif body_type == "urlencoded":
                assert DEFAULT_POST_CONTENT_TYPE in response["content-type"]
            else:
                raise ValueError("Unknown return format: %s" % body_type)
        elif response.status == 302: # redirect
            pass
        elif response.status == 500:
            raise Exception("ERROR: Something went wrong: %s" % content)
        else:
            raise Exception("ERROR: Something went wrong [%s]" % response.status)

        if body_type:
            return self.parse_response(respcls, content, body_type,
                                       state, extended)
        else:
            return response

    def do_authorization_request(self, cls=AuthorizationRequest,
                                 state="", body_type="", method="GET",
                                 request_args=None, extra_args=None,
                                 http_args=None, resp_cls=None):

        url, body, ht_args, csi = self.request_info(cls, method, request_args,
                                                    extra_args)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        resp = self.request_and_return(url, resp_cls, method, body,
                                       body_type, extended=False,
                                       state=state, http_args=http_args)

        if isinstance(resp, ErrorResponse):
            resp.state = csi.state

        return resp

    def do_access_token_request(self, cls=AccessTokenRequest, scope="",
                                state="", body_type="json", method="POST",
                                request_args=None, extra_args=None,
                                http_args=None, resp_cls=AccessTokenResponse,
                                authn_method="", **kwargs):

        # method is default POST
        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state,
                                                    authn_method=authn_method,
                                                    **kwargs)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       body_type, extended=False,
                                       state=state, http_args=http_args)

    def do_access_token_refresh(self, cls=RefreshAccessTokenRequest,
                                state="", body_type="json", method="POST",
                                request_args=None, extra_args=None,
                                http_args=None, resp_cls=AccessTokenResponse,
                                authn_method="", **kwargs):

        token = self.get_token(also_expired=True, state=state, **kwargs)

        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    token=token,
                                                    authn_method=authn_method)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       body_type, extended=False,
                                       state=state, http_args=http_args)

    def do_revocate_token(self, cls=TokenRevocationRequest, scope="", state="",
                          body_type="json", method="POST",
                          request_args=None, extra_args=None, http_args=None,
                          resp_cls=None, authn_method=""):

        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    request_args=request_args,
                                                    extra_args=extra_args,
                                                    scope=scope, state=state,
                                                    authn_method=authn_method)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       body_type, extended=False,
                                       state=state, http_args=http_args)

    def fetch_protected_resource(self, uri, method="GET", headers=None,
                                 state="", **kwargs):

        try:
            token = self.get_token(state=state, **kwargs)
        except ExpiredToken:
            # The token is to old, refresh
            self.do_access_token_refresh()
            token = self.get_token(state=state, **kwargs)

        if headers is None:
            headers = {}

        request_args = {"access_token": token.access_token}

        if "authn_method" in kwargs:
            http_args = self.init_authentication_method(request_args, **kwargs)
        else:
            # If nothing defined this is the default
            http_args = bearer_header(self, request_args, **kwargs)

        headers.update(http_args["headers"])

        return self.http.request(uri, method, headers=headers, **kwargs)

class Server(object):
    def __init__(self):
        pass

    def parse_url_request(self, cls, url=None, query=None, extended=False):
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        req = cls.set_urlencoded(query, extended)
        req.verify()
        return req

    def parse_authorization_request(self, rcls=AuthorizationRequest,
                                    url=None, query=None, extended=False):
        
        return self.parse_url_request(rcls, url, query, extended)

    def parse_jwt_request(self, rcls=AuthorizationRequest, txt="", key="",
                          verify=True, extend=False):
        areq = rcls.set_jwt(txt, key, verify, extend)
        areq.verify()
        return areq

    def parse_body_request(self, cls=AccessTokenRequest, body=None,
                           extend=False):
        req = cls.set_urlencoded(body, extend)
        req.verify()
        return req

    def parse_token_request(self, rcls=AccessTokenRequest, body=None,
                            extend=False):
        return self.parse_body_request(rcls, body, extend)

    def parse_refresh_token_request(self, rcls=RefreshAccessTokenRequest,
                                    body=None, extend=False):
        return self.parse_body_request(rcls, body, extend)

#    def is_authorized(self, path, authorization=None):
#        if not authorization:
#            return False
#
#        if authorization.startswith("Bearer"):
#            parts = authorization.split(" ")
#
#        return True


import hashlib
from Crypto.Cipher import AES

class Crypt():
    def __init__(self, password, mode=AES.MODE_CBC):
        self.password = password or 'kitty'
        self.key = hashlib.sha256(password).digest()
        self.mode = mode

    def encrypt(self, text):
        encryptor = AES.new(self.key, self.mode)

        if len(text) % 16:
            text += ' ' * (16 - len(text) % 16)
            
        return encryptor.encrypt(text)

    def decrypt(self, ciphertext):
        decryptor = AES.new(self.key, self.mode)
        return decryptor.decrypt(ciphertext)
    

if __name__ == "__main__":
    import doctest
    doctest.testmod()