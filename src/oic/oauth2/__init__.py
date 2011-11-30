#!/usr/bin/env python
#
__author__ = 'rohe0002'

import urllib
import urlparse
import json
import httplib2
import time
import jwt
import base64
import inspect

from oic.utils import time_util

Version = "2.0"

HTTP_ARGS = ["headers", "redirections", "connection_type"]

class MissingRequiredAttribute(Exception):
    def __init__(self, attr):
        Exception.__init__(self)
        self.attr = attr

    def __str__(self):
        return "Missing required attribute '%s'" % self.attr

class TooManyValues(Exception):
    pass

class GrantExpired(Exception):
    pass

class OldAccessToken(Exception):
    pass

class DecodeError(Exception):
    pass

class VerificationError(Exception):
    pass

#noinspection PyUnusedLocal
def sp_sep_list_serializer(vals, format="urlencoded", extended=False):
    if format == "urlencoded":
        return " ".join(vals)
    else:
        return vals

#noinspection PyUnusedLocal
def sp_sep_list_deserializer(val, format="urlencoded", extended=False):
    if format == "urlencoded":
        if isinstance(val, basestring):
            return val.split(" ")
        elif isinstance(val, list) and len(val) == 1:
            return val[0].split(" ")
    else:
        return val

#noinspection PyUnusedLocal
def json_serializer(obj, format="urlencoded", extended=False):
    return json.dumps(obj)

#noinspection PyUnusedLocal
def json_deserializer(txt, format="urlencoded", extended=False):
    return json.loads(txt)

class Base(object):
    c_attributes = {}

    def __init__(self, **kwargs):
        self.c_extension = {}
        for key, val in kwargs.items():
            self.c_extension[key] = val

    def get_urlencoded(self, extended=False, omit=None):
        """
        Creates a string using the application/x-www-form-urlencoded format

        :param extended: Allow parameter extension
        :param omit: A list of parameters that are not to be included when
            constructing the urlencoded form
        :return: A string of the application/x-www-form-urlencoded format
        """
        if omit is None:
            omit = []
            
        params = []
        for (attribute, (_, req, _ser, _)) in self.c_attributes.items():
            if attribute in omit:
                continue
            val = getattr(self, attribute)
            # Should I allow parameters with "" as value ???
            if val is None or val == []:
                if req:
                    raise MissingRequiredAttribute("%s" % attribute)
            else:
                if isinstance(val, basestring):
                    params.append((attribute, str(val)))
                elif isinstance(val, list):
                    if _ser:
                        params.append((attribute, str(_ser(val,
                                                           format="urlencoded",
                                                           extended=extended))))
                    else:
                        for item in val:
                            params.append((attribute, str(item)))
                else:
                    params.append((attribute, str(val)))
        if extended:
            for key, val in self.c_extension.items():
                if key in omit:
                    continue
                if isinstance(val, basestring):
                    params.append((key,val))
                elif isinstance(val, list):
                    item = " ".join([str(v) for v in val])
                    params.append((key,item))
                else:
                    params.append((key, str(val)))

        return urllib.urlencode(params)

    def to_urlencoded(self, extended=False, omit=None):
        return self.get_urlencoded(extended, omit)

    @classmethod
    def set_urlencoded(cls, urlencoded, extended=False):
        """
        from a string of the application/x-www-form-urlencoded format creates
        a class instance

        :param cls: The class to instantiate
        :param urlencoded: The string
        :param extended: If parameter extension is to be allowed
        :return: An instance of the cls class
        """
        argv = {}
        extension = {}
        #parse_qs returns a dictionary with keys and values. The values are
        #always lists even if there is only one value in the list.
        #keys only appears once.
        for key, val in urlparse.parse_qs(urlencoded).items():
            if key in cls.c_attributes:
                (typ, _, _, _deser) = cls.c_attributes[key]
                if isinstance(typ, list):
                    if _deser:
                        argv[key] = _deser(val[0], "urlencoded", extended)
                    else:
                        argv[key] = val
                else: # must be single value
                    if len(val) == 1:
                        if _deser:
                            argv[key] = _deser(val[0], "urlencoded", extended)
                        elif isinstance(val[0], typ):
                            argv[key] = val[0]
                        else:
                            try:
                                argv[key] = typ(val[0])
                            except Exception:
                                raise
                    else:
                        raise TooManyValues
            elif extended:
                if len(val) == 1:
                    extension[key] = val[0]
                else:
                    extension[key] = val
            #ignore attributes I don't know about

        if extended and extension:
            argv.update(extension)
            
        return cls(**argv)

    @classmethod
    def from_urlencoded(cls, urlencoded, extended=False):
        return cls.set_urlencoded(urlencoded, extended)

    def dictionary(self, extended=False):
        """
        Return a dictionary representation of the class

        :param extended: Allow parameter extension
        :return: A dict
        """
        dic = {}
        for (attribute, (typ, _, ser, _)) in self.c_attributes.items():
            val = getattr(self, attribute)
            if val is None or val == [] or val == "":
                pass
            else:
                if ser:
                    val = ser(val, format="dict", extended=extended)
                elif isinstance(val, Base):
                    val = val.dictionary(extended=extended)
                elif isinstance(val, list) and isinstance(val[0], Base):
                    val = [v.dictionary(extended=extended) for v in val]
                dic[attribute] = val
        if extended:
            dic.update(self.c_extension)
        return dic
    
    def get_json(self, extended=False):
        """
        Return a JSON representation of the class instance

        :param extended: Allow parameter extension
        :return: A JSON encoded string
        """
        dic = self.dictionary(extended)
        return json.dumps(dic)

    @classmethod
    def set_json(cls, txt, extended=False):
        """
        Given a JSON text representation create a class instance

        Direct translation so the value for one key might be a list or a
        single value.

        :param cls: The type of class
        :param extended: Whether parameter extension should be allowed
        :return: A class instance or raise an exception on error
        """
        args = {}
        extension = {}

        for key, val in json.loads(txt).items():
            # Earlier versions of python don't like unicode strings as
            # variable names
            skey = str(key)
            if key in cls.c_attributes:
                (vtyp, req, _, _deser) = cls.c_attributes[key]
                if isinstance(vtyp, list):
                    vtype = vtyp[0]
                    if isinstance(val, vtype):
                        args[skey] = [val]
                    elif isinstance(val, list):
                        if _deser:
                            val = _deser(val, format="dict", extended=extended)

                        if issubclass(vtype, Base):
                            args[skey] = [
                                vtype(**dict([(str(x),
                                               y) for x,y
                                                  in v.items()])) for v in val]
                        else:
                            for v in val:
                                if not isinstance(v, vtype):
                                    raise ValueError("Wrong type != %s" % vtype)

                            args[skey] = val
                    else:
                        raise ValueError("Wrong type != %s" % vtype)
                else:
                    if isinstance(val, basestring):
                        args[skey] = val
                    elif isinstance(val, list):
                        if len(val) == 1:
                            args[skey] = val[0]
                        else:
                            raise TooManyValues
                    else:
                        if issubclass(vtyp, Base):
                            val = dict([(str(k), v) for k,v in val.items()])
                            args[skey] = vtyp(**val)
                        else:
                            args[skey] = val
            elif extended:
                extension[skey] = val
            #ignore attributes I don't know about

        if extended and extension:
            args.update(extension)

        return cls(**args)

    def to_json(self, extended=False):
        return self.get_json(extended)

    @classmethod
    def from_json(cls, txt, extended=False):
        return cls.set_json(txt, extended)

    def get_jwt(self, extended=False, key="", algorithm=""):
        """
        Create a signed JWT representation of the class instance
        draft-jones-json-web-signature-02

        :param extended: Whether parameter extension should be allowed
        :param key: The signing key
        :param algorithm: The signature algorithm to use
        :return: A signed JWT
        """
        if not algorithm:
            algorithm = "HS256"
        return jwt.encode(self.get_json(extended), key, algorithm)

    @classmethod
    def set_jwt(cls, txt, key="", verify=True, extended=False):
        """
        Given a signed JWT, verify its correctness and then create a class
        instance from the content.

        :param cls: Then type of class
        :param txt: The JWT
        :param key: The key that supposedly used to sign the JWT
        :param verify: Whether the signature should be verified or not
        :param extended: Whether parameter extension should be allowed
        :return: A class instance
        """
        jso = jwt.decode(txt, key, verify)
        return cls.set_json(jso, extended)

    def to_jwt(self, extended=False, key="", algorithm=""):
        return self.get_jwt(extended, key, algorithm)

    @classmethod
    def from_jwt(cls, txt, key="", verify=True, extended=False):
        return cls.set_jwt(txt, key, verify, extended)

    def __str__(self):
        return self.get_urlencoded()

    def _isinstance(self, val, typ):
        """
        Make sure that the values are of the correct type
        Raises an ValueError exception if this isn't the case.

        :param: the value or values
        :param: a specification of the value type
        """
        if isinstance(typ, str):
            if not isinstance(val, typ):
                raise ValueError
        elif isinstance(typ, list):
            if isinstance(val, list): # If one is a list then both must be
                _typ = typ[0]
                for item in val:
                    self._isinstance(item, _typ)
        else:
            if not isinstance(val, typ):
                raise ValueError("value: '%s' not of type '%s'" % (val, typ))

    def verify(self):
        """
        Make sure all the required values are there and that the values are
        of the correct type
        """
        for (attribute, (typ, required, _, _)) in self.c_attributes.items():
            val = getattr(self, attribute)
            if val is None or val == []:
                if required:
                    raise MissingRequiredAttribute("%s" % attribute)
            else:
                self._isinstance(val, typ)

        return True

    def keys(self):
        """
        Return a list of attribute/keys/parameters of this class that has
        values.

        :return: A list of attribute names
        """
        res = []
        for key in self.c_attributes.keys():
            if getattr(self, key):
                res.append(key)

        res.extend(self.c_extension.keys())

        return res

    def __getitem__(self, item):
        return getattr(self, item)

    def items(self):
        return self.dictionary(extended=True).items()

    def __getattr__(self, item):
        return self.c_extension[item]
#
# =============================================================================
#

SINGLE_REQUIRED_STRING = (basestring, True, None, None)
SINGLE_OPTIONAL_STRING = (basestring, False, None, None)
SINGLE_OPTIONAL_INT = (int, False, None, None)
OPTIONAL_LIST_OF_STRINGS = ([basestring], False, sp_sep_list_serializer,
                            sp_sep_list_deserializer)
REQUIRED_LIST_OF_STRINGS = ([basestring], True,
                            sp_sep_list_serializer,
                            sp_sep_list_deserializer)
SINGLE_OPTIONAL_JSON = (basestring, False, json_serializer, json_deserializer)


class ErrorResponse(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["error"] = SINGLE_REQUIRED_STRING
    c_attributes["error_description"] = SINGLE_OPTIONAL_STRING
    c_attributes["error_uri"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 error=None,
                 error_description=None,
                 error_uri=None,
                 **kwargs):
        Base.__init__(self, **kwargs)
        self.error = error
        self.error_description = error_description
        self.error_uri = error_uri

class AuthorizationErrorResponse(ErrorResponse):
    c_attributes = ErrorResponse.c_attributes.copy()
    c_attributes["state"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 error=None,
                 error_description=None,
                 error_uri=None,
                 state=None,
                 **kwargs):
        ErrorResponse.__init__(self,
                               error,
                               error_description,
                               error_uri,
                               **kwargs)
        self.state = state

    def verify(self):
        if self.error:
            if self.error in ["invalid_request", "unathorized_client",
                              "access_denied", "unsupported_response_type",
                              "invalid_scope", "server_error",
                              "temporarily_unavailable"]:
                pass
            else:
                raise ValueError("'%s' not an valid error type" % self.error)

        return ErrorResponse.verify(self)

class TokenErrorResponse(ErrorResponse):
    c_attributes = ErrorResponse.c_attributes.copy()

    def __init__(self,
                 error=None,
                 error_description=None,
                 error_uri=None,
                 **kwargs):
        ErrorResponse.__init__(self,
                               error,
                               error_description,
                               error_uri,
                               **kwargs)

    def verify(self):
        if self.error:
            if not self.error in ["invalid_request", "invalid_client",
                              "invalid_grant", "unauthorized_client",
                              "unsupported_grant_type", "invalid_scope"]:
                raise ValueError("'%s' not an valid error type" % self.error)

        return ErrorResponse.verify(self)

class AccessTokenResponse(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["access_token"] = SINGLE_REQUIRED_STRING
    c_attributes["token_type"] = SINGLE_REQUIRED_STRING
    c_attributes["expires_in"] = SINGLE_OPTIONAL_INT
    c_attributes["refresh_token"] = SINGLE_OPTIONAL_STRING
    c_attributes["scope"] = OPTIONAL_LIST_OF_STRINGS
    #c_attributes["state"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 access_token=None,
                 token_type=None,
                 expires_in=None,
                 refresh_token=None,
                 scope=None,
                 **kwargs):
        Base.__init__(self, **kwargs)
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in
        self.refresh_token = refresh_token
        self.scope = scope or []

class AccessTokenRequest(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["grant_type"] = SINGLE_REQUIRED_STRING
    c_attributes["code"] = SINGLE_REQUIRED_STRING
    c_attributes["redirect_uri"] = SINGLE_REQUIRED_STRING
    c_attributes["client_id"] = SINGLE_REQUIRED_STRING
    c_attributes["client_secret"] = SINGLE_OPTIONAL_STRING

    def __init__(self, grant_type=None,
                 code=None,
                 redirect_uri=None,
                 client_id=None,
                 client_secret=None,
                 **kwargs):
        Base.__init__(self, **kwargs)
        self.grant_type = grant_type
        self.code = code
        self.redirect_uri = redirect_uri
        self.client_id = client_id
        self.client_secret = client_secret

class AuthorizationRequest(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["response_type"] = REQUIRED_LIST_OF_STRINGS
    c_attributes["client_id"] = SINGLE_REQUIRED_STRING
    c_attributes["redirect_uri"] = SINGLE_OPTIONAL_STRING
    c_attributes["scope"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["state"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 response_type=None,
                 client_id=None,
                 redirect_uri=None,
                 scope=None,
                 state=None,
                 **kwargs):
        Base.__init__(self, **kwargs)
        self.response_type = response_type or []
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope or []
        self.state = state

class AuthorizationResponse(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["code"] = SINGLE_REQUIRED_STRING
    c_attributes["state"] = SINGLE_OPTIONAL_STRING

    def __init__(self, code=None, state=None, **kwargs):
        Base.__init__(self, **kwargs)
        self.code = code
        self.state = state

class ROPCAccessTokenRequest(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["grant_type"] = SINGLE_REQUIRED_STRING
    c_attributes["username"] = SINGLE_REQUIRED_STRING
    c_attributes["password"] = SINGLE_REQUIRED_STRING
    c_attributes["scope"] = SINGLE_OPTIONAL_STRING

    def __init__(self, grant_type="password", username=None, password=None,
                 scope=None, **kwargs):
        Base.__init__(self, **kwargs)
        self.grant_type = grant_type
        self.username = username
        self.password = password
        self.scope = scope

    def verify(self):
        assert self.grant_type == "password"
        return Base.verify(self)

class CCAccessTokenRequest(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["grant_type"] = SINGLE_REQUIRED_STRING
    c_attributes["scope"] = SINGLE_OPTIONAL_STRING

    def __init__(self, grant_type="client_credentials", scope=None, **kwargs):
        Base.__init__(self,**kwargs)
        self.grant_type = grant_type
        self.scope = scope

    def verify(self):
        assert self.grant_type == "client_credentials"
        return Base.verify(self)

class RefreshAccessTokenRequest(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["grant_type"] = SINGLE_REQUIRED_STRING
    c_attributes["refresh_token"] = SINGLE_REQUIRED_STRING
    c_attributes["client_id"] = SINGLE_REQUIRED_STRING
    c_attributes["scope"] = SINGLE_OPTIONAL_STRING
    c_attributes["client_secret"] = SINGLE_OPTIONAL_STRING

    def __init__(self, grant_type="refresh_token",
                 refresh_token=None,
                 client_id=None,
                 scope=None,
                 client_secret=None,
                 **kwargs):
        Base.__init__(self, **kwargs)
        self.grant_type = grant_type
        self.refresh_token = refresh_token
        self.client_id = client_id
        self.scope = scope
        self.client_secret = client_secret

    def verify(self):
        assert self.grant_type == "refresh_token"
        return Base.verify(self)


class TokenRevocationRequest(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["token"] = SINGLE_REQUIRED_STRING

    def __init__(self, token=None, **kwargs):
        Base.__init__(self, **kwargs)
        self.token = token


# =============================================================================

def factory(cls, **argv):
    _dict = {}
    for attr in cls.c_attributes:
        try:
            _dict[attr] = argv[attr]
        except KeyError:
            pass

    return cls(**_dict)

DEFAULT_POST_CONTENT_TYPE = 'application/x-www-form-urlencoded'

REQUEST2ENDPOINT = {
    AuthorizationRequest: "authorization_endpoint",
    AccessTokenRequest: "token_endpoint",
#    ROPCAccessTokenRequest: "authorization_endpoint",
#    CCAccessTokenRequest: "authorization_endpoint",
    RefreshAccessTokenRequest: "token_endpoint",
    TokenRevocationRequest: "token_endpoint",
}

RESPONSE2ERROR = {
    AuthorizationResponse: [AuthorizationErrorResponse, TokenErrorResponse],
    AccessTokenResponse: [TokenErrorResponse]
}

class Grant(object):
    def __init__(self, state="", gexp_in=600):
        self.state = state
        self.grant_expiration_time = 0
        self.token_expiration_time = 0
        self.gexp_in = gexp_in

    @classmethod
    def from_code(cls, resp):
        instance = cls()
        instance.add_code(resp)
        return instance

    def add_code(self, resp):
        self.code = resp.code
        self.grant_expiration_time = time_util.time_sans_frac() + self.gexp_in

    def valid_code(self):
        if time.time() > self.grant_expiration_time:
            return False
        else:
            return True

    @classmethod
    def from_token(cls, atr):
        instance = cls()
        instance.add_token(atr)
        return instance

    def add_token(self, atr):
        for prop in AccessTokenResponse.c_attributes.keys():
            _val = getattr(atr, prop)
            if _val:
                setattr(self, prop, _val)

        for key, val in atr.c_extension.items():
            setattr(self, key, val)
            
        if atr.expires_in:
            _tet = time_util.time_sans_frac() + int(atr.expires_in)
        else:
            _tet = 0
        self.token_expiration_time = int(_tet)

    def valid_token(self):
        if self.token_expiration_time:
            if time.time() > self.token_expiration_time:
                return False

        return True

    def __str__(self):
        return "%s" % self.__dict__

    def keys(self):
        return self.__dict__.keys()

    def update(self, resp):
        if isinstance(resp, AccessTokenResponse):
            self.add_token(resp)
        elif isinstance(resp, AuthorizationResponse):
            self.add_code(resp)

    @classmethod
    def set(cls, resp):
        instance = cls()

        if isinstance(resp, AccessTokenResponse):
            instance.add_token(resp)
        elif isinstance(resp, AuthorizationResponse):
            instance.add_code(resp)
        else:
            return None
        
        return instance

class Client(object):
    def __init__(self, client_id=None, cache=None, http_timeout=None,
                 proxy_info=None, follow_redirects=True,
                 disable_ssl_certificate_validation=False,
                 ca_certs="", key=None,
                 algorithm="HS256", grant_expire_in=600, client_secret="",
                 client_timeout=0):

        self.http = httplib2.Http(cache, http_timeout, proxy_info, ca_certs,
            disable_ssl_certificate_validation=disable_ssl_certificate_validation)
        self.http.follow_redirects = follow_redirects

        self.client_id = client_id
        self.client_secret = client_secret
        self.client_timeout = client_timeout

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

        self.key = key
        self.algorithm = algorithm

    def reset(self):
        self.state = None
        self.nonce = None

        self.grant = {}

        self.authorization_endpoint=None
        self.token_endpoint=None
        self.redirect_uri = None

    def grant_from_state(self, state):
        for grant in self.grant.values():
            if grant.state == state:
                return grant

        return None

    def scope_from_state(self, state):
        for scope, grant in self.grant.items():
            if grant.state == state:
                return scope

        return None
    
    def grant_from_state_or_scope(self, state, scope):
        grant = None
        
        if state:
            grant = self.grant_from_state(state)

        if grant is None:
            try:
                grant = self.grant[scope]
            except KeyError:
                pass

        return grant

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

    def access_token_is_valid(self, scope=""):
        return self.grant[scope].valid_token()

    def construct_request(self, reqclass, request_args=None, extra_args=None):
        if request_args is None:
            request_args = {}
            
        args = self._parse_args(reqclass, **request_args)
        if extra_args:
            args.update(extra_args)
        return reqclass(**args)

    #noinspection PyUnusedLocal
    def construct_AuthorizationRequest(self, reqclass=AuthorizationRequest,
                                       scope="", state="", request_args=None,
                                       extra_args=None):

        if request_args is not None:
            try: # change default
                self.redirect_uri = request_args["redirect_uri"]
            except KeyError:
                pass

        return self.construct_request(reqclass, request_args, extra_args)

    def construct_AccessTokenRequest(self, cls=AccessTokenRequest, scope="",
                                     state="", request_args=None,
                                     extra_args=None):

        grant = self.grant_from_state_or_scope(state, scope)
        if not grant:
            raise Exception("Missing grant")

        if not grant.valid_code():
            raise GrantExpired("Authorization Code to old %s > %s" % (time.time(),
                                                grant.grant_expiration_time))

        if request_args is None:
            request_args = {}

        request_args["code"] = grant.code

        if "grant_type" not in request_args:
            request_args["grant_type"] = "authorization_code"

        return self.construct_request(cls, request_args, extra_args)

    def construct_RefreshAccessTokenRequest(self,
                                            cls=RefreshAccessTokenRequest,
                                            scope="", state="",
                                            request_args=None,
                                            extra_args=None):

        if request_args is None:
            request_args = {}
            
        grant = self.grant_from_state_or_scope(state, scope)
        request_args["refresh_token"] = grant.refresh_token

        if not scope and state:
            scope = self.scope_from_state(state)
            
        request_args["scope"] = scope
        
        return self.construct_request(cls, request_args, extra_args)

    def construct_TokenRevocationRequest(self, cls=TokenRevocationRequest,
                                         scope="", state="", request_args=None,
                                         extra_args=None):

        if request_args is None:
            request_args = {}

        grant = self.grant_from_state_or_scope(state, scope)

        request_args["token"] = grant.access_token
        return self.construct_request(cls, request_args, extra_args)

    def request_info(self, cls, method="POST", scope="",
                     state="", request_args=None, extra_args=None):

        if request_args is None:
            request_args = {}
            
        cis = getattr(self, "construct_%s" % cls.__name__)(cls, scope, state,
                                                           request_args,
                                                           extra_args)

        uri = self._endpoint(REQUEST2ENDPOINT[cls], **request_args)

        if extra_args:
            extend = True
        else:
            extend = False

        if method == "POST":
            body = cis.get_urlencoded(extended=extend)
        else: # assume GET
            uri = "%s?%s" % (uri, cis.get_urlencoded(extended=extend))
            body = None

        if method == "POST":
            h_args = {"headers": {"content-type": DEFAULT_POST_CONTENT_TYPE}}
        else:
            h_args = {}

        return uri, body, h_args, cis

#    def _error(self, cls, info, err="", extended=False):
#        resp = RESPONSE2ERROR[cls](error="invalid_request",
#                                   description="failed with '%s' on '%s'" % (
#                                                                    err, info))
#        assert resp.verify()
#        return resp

    def parse_response(self, cls, info="", format="json",
                       scope="", state="", extended=False):
        """
        Parse a response

        :param cls: Which class to use when parsing the response
        :param info: The response, can be either an JSON code or an urlencoded
            form:
        :param format: Which serialization that was used
        :param extended: If non-standard parametrar should be honored
        :return: The parsed and to some extend verified response
        """

        resp = None
        if format == "json":
            try:
                resp = cls.set_json(info, extended)
                assert resp.verify()
            except Exception, err:
                aresp = resp
                serr = ""

                for errcls in RESPONSE2ERROR[cls]:
                    try:
                        resp = errcls.set_json(info, extended)
                        resp.verify()
                        break
                    except Exception, serr:
                        resp = None

                if not resp:
                    if aresp and aresp.keys():
                        raise ValueError("Parse error: %s" % err)
                    else:
                        raise ValueError("Parse error: %s" % serr)

        elif format == "urlencoded":
            if '?' in info:
                parts = urlparse.urlparse(info)
                scheme, netloc, path, params, query, fragment = parts[:6]
            else:
                query = info

            try:
                resp = cls.set_urlencoded(query, extended)
                assert resp.verify()
            except Exception, err:
                aresp = resp
                serr = ""

                for errcls in RESPONSE2ERROR[cls]:
                    try:
                        resp = errcls.set_urlencoded(query, extended)
                        resp.verify()
                        break
                    except Exception, serr:
                        resp = None

                if not resp:
                    if aresp and aresp.keys():
                        raise ValueError("Parse error: %s" % err)
                    else:
                        raise ValueError("Parse error: %s" % serr)

        else:
            raise Exception("Unknown package format: '%s'" %  format)

        try:
            self.grant[scope].update(resp)
        except KeyError:
            if state:
                grant = self.grant_from_state(state)
            else:
                grant = None

            if not grant:
                grant = Grant.set(resp)
                
            if grant:
                self.grant[scope] = grant

        return resp

    def request_and_return(self, url, respcls=None, method="GET", body=None,
                        return_format="json", extended=True, scope="",
                        state="", http_args=None):
        """
        :param url: The URL to which the request should be sent
        :param respcls: The class the should represent the response
        :param method: Which HTTP method to use
        :param body: A message body if any
        :param return_format: The format of the body of the return message
        :param extended: If non-standard parametrar should be honored
        :param http_args: Arguments for the HTTP client
        :return: A respcls or ErrorResponse instance or True if no response
            body was expected.
        """

        if http_args is None:
            http_args = {}

        if "password" in http_args:
            self.http.add_credentials(self.client_id, http_args["password"])

        try:
            response, content = self.http.request(url, method, body=body,
                                                  **http_args)
        except Exception:
            raise

        if response.status == 200:
            if return_format == "":
                pass
            elif return_format == "json":
                assert "application/json" in response["content-type"]
            elif return_format == "urlencoded":
                assert DEFAULT_POST_CONTENT_TYPE in response["content-type"]
            else:
                raise ValueError("Unknown return format: %s" % return_format)
        elif response.status == 500:
            raise Exception("ERROR: Something went wrong: %s" % content)
        else:
            raise Exception("ERROR: Something went wrong [%s]" % response.status)

        if return_format:
            return self.parse_response(respcls, content, return_format,
                                       scope, state, extended)
        else:
            return True

    def do_authorization_request(self, cls=AuthorizationRequest, scope="",
                                 state="", return_format="", method="GET",
                                 request_args=None, extra_args=None,
                                 http_args=None, resp_cls=None):

        url, body, ht_args, csi = self.request_info(cls,
                                                    request_args=request_args,
                                                    extra_args=extra_args)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        resp = self.request_and_return(url, resp_cls, method, body,
                                       return_format, extended=False,
                                       scope=scope, state=state,
                                       http_args=http_args)

        if isinstance(resp, ErrorResponse):
            resp.state = csi.state

        return resp

    def do_access_token_request(self, cls=AccessTokenRequest, scope="",
                                state="", return_format="json", method="POST",
                                request_args=None, extra_args=None,
                                http_args=None, resp_cls=AccessTokenResponse):

        # method is default POST
        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    scope=scope, state=state,
                                                    request_args=request_args,
                                                    extra_args=extra_args)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       return_format, extended=False,
                                       scope=scope, state=state,
                                       http_args=http_args)

    def do_access_token_refresh(self, cls=RefreshAccessTokenRequest, scope="",
                                state="", return_format="json", method="POST",
                                request_args=None, extra_args=None,
                                http_args=None, resp_cls=AccessTokenResponse):

        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    scope=scope, state=state,
                                                    request_args=request_args,
                                                    extra_args=extra_args)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       return_format, extended=False,
                                       scope=scope, state=state,
                                       http_args=http_args)

    def do_revocate_token(self, cls=TokenRevocationRequest, scope="", state="",
                          return_format="json", method="POST",
                          request_args=None, extra_args=None, http_args=None,
                          resp_cls=None):

        url, body, ht_args, csi = self.request_info(cls, method=method,
                                                    scope=scope, state=state,
                                                    request_args=request_args,
                                                    extra_args=extra_args)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return self.request_and_return(url, resp_cls, method, body,
                                       return_format, extended=False,
                                       scope=scope, state=state,
                                       http_args=http_args)

    def fetch_protected_resource(self, uri, method="GET", headers=None,
                                 scope="", **kwargs):

        if not self.access_token_is_valid():
            # The token is to old, refresh
            self.do_access_token_refresh()

        if headers is None:
            headers = {}

        try:
            _acc_token = kwargs["access_token"]
            del kwargs["access_token"]
        except KeyError:
            _acc_token= self.grant[scope].access_token

        headers["Authorization"] = "Bearer %s" % base64.encodestring(_acc_token)

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