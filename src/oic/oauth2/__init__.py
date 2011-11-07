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

class TimerTimedOut(Exception):
    pass

class OldAccessToken(Exception):
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
                pass
            else:
                if isinstance(val, basestring):
                    params.append((attribute, str(val)))
                elif isinstance(val, list):
                    if _ser:
                        params.append((attribute, str(_ser(val))))
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
                    for item in val:
                        params.append((key,item))
                else:
                    params.append((key,val))

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
                        argv[key] = _deser(val[0])
                    else:
                        argv[key] = val
                else: # must be single value
                    if len(val) == 1:
                        if isinstance(val[0], typ):
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
            if key in cls.c_attributes:
                (vtyp, req, _, _deser) = cls.c_attributes[key]
                if isinstance(vtyp, list):
                    vtype = vtyp[0]
                    if isinstance(val, vtype):
                        args[key] = [val]
                    elif isinstance(val, list):
                        if _deser:
                            val = _deser(val, format="json", extended=extended)

                        if issubclass(vtype, Base):
                            args[key] = [vtype(**v) for v in val]
                        else:
                            for v in val:
                                if not isinstance(v, vtype):
                                    raise ValueError("Wrong type != %s" % vtype)

                            args[key] = val
                    else:
                        raise ValueError("Wrong type != %s" % vtype)
                else:
                    if isinstance(val, basestring):
                        args[key] = val
                    elif isinstance(val, list):
                        if len(val) == 1:
                            args[key] = val[0]
                        else:
                            raise TooManyValues
                    else:
                        if issubclass(vtyp, Base):
                            args[key] = vtyp(**val)
                        else:
                            args[key] = val
            elif extended:
                extension[key] = val
            #ignore attributes I don't know about

        if extended and extension:
            args.update(extension)

        return cls(**args)

    def to_json(self, extended=False):
        return self.get_json(extended)

    @classmethod
    def from_json(cls, extended=False):
        return cls.set_json(extended)

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
        for key in self.c_extension.keys():
            if getattr(self, key):
                res.append(key)
        return res

    def __getitem__(self, item):
        return getattr(self, item)

    def items(self):
        return self.dictionary(extended=True).items()
    
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
            if not self.error in ["invalid_request",
                                  "unathorized_client",
                                  "access_denied",
                                  "unsupported_response_type",
                                  "invalid_scope",
                                  "server_error",
                                  "temporarily_unavailable"]:
                raise ValueError("'%s' not an valid error type" % self.error)

        return Base.verify(self)

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
            if not self.error in ["invalid_request",
                                  "invalid_client",
                                  "invalid_grant",
                                  "unauthorized_client",
                                  "unsupported_grant_type",
                                  "invalid_scope"]:
                raise ValueError("'%s' not an allowed error type" % self.error)

        return Base.verify(self)

class AccessTokenResponse(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["access_token"] = SINGLE_REQUIRED_STRING
    c_attributes["token_type"] = SINGLE_REQUIRED_STRING
    c_attributes["expires_in"] = SINGLE_OPTIONAL_INT
    c_attributes["refresh_token"] = SINGLE_OPTIONAL_STRING
    c_attributes["scope"] = OPTIONAL_LIST_OF_STRINGS
    c_attributes["state"] = SINGLE_OPTIONAL_STRING

    def __init__(self,
                 access_token=None,
                 token_type=None,
                 expires_in=None,
                 refresh_token=None,
                 scope=None,
                 state=None,
                 **kwargs):
        Base.__init__(self, **kwargs)
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in
        self.refresh_token = refresh_token
        self.scope = scope or []
        self.state = state

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

class Client(object):
    def __init__(self, client_id=None, cache=None, timeout=None,
                 proxy_info=None, follow_redirects=True,
                 disable_ssl_certificate_validation=False, key=None,
                 algorithm="HS256", expire_in=600):

        self.http = httplib2.Http(cache, timeout, proxy_info,
            disable_ssl_certificate_validation=disable_ssl_certificate_validation)
        self.http.follow_redirects = follow_redirects

        self.client_id = client_id
        self.state = None
        self.nonce = None

        self.authorization_code = None
        self.expire_in = expire_in
        self.grant_expiration_time = 0
        self.scope = None
        self.access_token = None
        self.token_expiration_time = 0

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

        self.authorization_code = None
        self.expire_in = 600
        self.grant_expiration_time = 0
        self.scope = None
        self.access_token = None
        self.token_expiration_time = 0

        self.authorization_endpoint=None
        self.token_endpoint=None
        self.redirect_uri = None

    def _parse_args(self, klass, **kwargs):
        ar_args = {}
        for prop, val in kwargs.items():
            if prop in klass.c_attributes:
                ar_args[prop] = val
            elif prop.startswith("extra_"):
                if prop[6:] not in AuthorizationRequest.c_attributes:
                    ar_args[prop[6:]] = val

        for prop in ["redirect_uri", "scope", "state", "client_id"]:
            if prop not in ar_args:
                ar_args[prop] = getattr(self, prop)

        return ar_args

    def _endpoint(self, endpoint, **kwargs):
        try:
            uri = kwargs[endpoint]
            del kwargs[endpoint]
        except KeyError:
            try:
                uri = getattr(self, endpoint)
            except Exception:
                raise Exception("No '%s' specified" % endpoint)
        return uri

    def access_token_is_valid(self):
        if not self.token_expiration_time:
            return True
        elif self.token_expiration_time >= time.time():
            return True
        else:
            return False
        
    def get_authorization_request(self, arclass=AuthorizationRequest,
                                  response_type=None, **kwargs):
        """
        Constructs an authorization request

        >>> client = Client()
        >>> client.redirect_uri = "https://www.example.com/authz"
        >>> client.client_id = "a1b2c3"
        >>> ar = client.get_authorization_request(response_type=["code"])
        >>> ar.client_id
        'a1b2c3'
        >>> ar.redirect_uri
        'https://www.example.com/authz'
        >>> ar.response_type
        ['code']
        >>> print ar
        redirect_uri=https%3A%2F%2Fwww.example.com%2Fauthz&response_type=code&client_id=a1b2c3

        Extra arguments should be prefixed with 'extra_'.
        This prefix is removed when constructing the urlencoded string

        >>> ar = client.get_authorization_request(response_type=["token"],extra_arg="overdrive")
        >>> ar.response_type
        ['token']
        >>> ar.c_extension
        {'arg': ['overdrive']}
        >>> ar.get_urlencoded(extended=True)
        'redirect_uri=https%3A%2F%2Fwww.example.com%2Fauthz&response_type=token&client_id=a1b2c3&arg=overdrive'

        :param arclass: Which AuthorizationRequest class to use
            this is only needed when you want to extend OAuth2
        :param response_type: The type of response you expect
            ("code"/"token"/..)
        :return: An 'arclass' instance
        """
        ar_args = self._parse_args(arclass, **kwargs)
        if "redirect_uri" in ar_args: # change default
            self.redirect_uri = ar_args["redirect_uri"]
        else:
            ar_args["redirect_uri"] = self.redirect_uri
        if "client_id" not in ar_args:
            ar_args["client_id"] = self.client_id

        return arclass(response_type, **ar_args)

    def get_authorization_request_with_request(self,
                                               arclass=AuthorizationRequest,
                                               response_type=None, **kwargs):
        inst = self.get_authorization_request(arclass, response_type, **kwargs)
        inst.request = inst.get_jwt(key=self.key, algorithm=self.algorithm)
        return inst

    def get_authorization_request_on_side(self, arclass=AuthorizationRequest,
                                               response_type=None, **kwargs):
        inst = self.get_authorization_request(arclass, response_type, **kwargs)
        request = inst.get_jwt(key=self.key, algorithm=self.algorithm)
        return inst, request

    def set_from_authorization_response(self, aresp):
        self.authorization_response = aresp
        self.grant_expiration_time = time.time()+self.expire_in
        self.authorization_code = aresp.code
        self.state = aresp.state

    def parse_authorization_response(self, arclass=AuthorizationResponse,
                                     url="", query=""):
        """
        Parses the authorization response.
        It also verifies that the response is correct. That is contains all
        the required parameters.

        >>> client = Client()
        >>> response = "state=sensommar&code=4885ed3b89c09"
        >>> ar = client.parse_authorization_response(query=response)
        >>> ar.code
        '4885ed3b89c09'
        >>> ar.state
        'sensommar'

        >>> url = "https://example.com/authz?state=latesummer&code=ba43a7ccae3d"
        >>> ar = client.parse_authorization_response(url=url)
        >>> ar.code
        'ba43a7ccae3d'
        >>> ar.state
        'latesummer'

        :param arclass: Which class to use when parsing the response
        :param url: The complete redirect URL
        :param query: Only the query part of the URL. If both 'url' and 'query'
            are given 'query' is ignored.
        :return: An instance of the 'arclass' class
        """
        if url:
            parts = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parts[:6]

        try:
            aresp = arclass.set_urlencoded(query)
            assert aresp.verify()
            self.set_from_authorization_response(aresp)
        except Exception:
            # Could be an error response
            aresp = AuthorizationErrorResponse.set_urlencoded(query)
            assert aresp.verify()

        return aresp

    def get_access_token_request(self, atr=AccessTokenRequest, **kwargs):
        """
        Construct an AccessTokenRequest

        >>> import time
        >>> client = Client()
        >>> client.redirect_uri = "https://www.example.com/authz"
        >>> client.grant_expiration_time = time.time()+5
        >>> atr = client.get_access_token_request()
        >>> atr.redirect_uri
        'https://www.example.com/authz'
        >>> atr.grant_type
        'authorization_code'

        :param atr: Which class to use when constructing the request
        :return: An instance of the class
        """
        if time.time() > self.grant_expiration_time:
            raise TimerTimedOut("Authorization Code to old %s > %s" % (
                                    time.time(), self.grant_expiration_time))

        ar_args = self._parse_args(atr, **kwargs)
        ar_args["redirect_uri"]=self.redirect_uri
        ar_args["code"] = self.authorization_code

        if "grant_type" not in ar_args:
            ar_args["grant_type"] = "authorization_code"

        if "client_id" not in ar_args:
            ar_args["client_id"] = self.client_id
            
        return atr(**ar_args)


    def set_from_access_token(self, atr):
        for prop in atr.c_attributes.keys():
            setattr(self, prop, getattr(atr, prop))

    def parse_access_token_response(self, cls=AccessTokenResponse, info="",
                                    format="json", extended=False):
        """
        Parse an Access Token response

        :param cls: Which class to use when parsing the response
        :param info: The response, can be either an JSON code or an urlencoded
            form:
        :param format: Which serialization that was used
        :param extended: If non-standard parametrar should be honored
        :return: The parsed and to some extend verified response
        """
        if format == "json":
            try:
                atr = cls.set_json(info, extended)
            except Exception:
                atr = ErrorResponse.set_json(info, extended)
        elif format == "urlencoded":
            if '?' in info:
                parts = urlparse.urlparse(info)
                scheme, netloc, path, params, query, fragment = parts[:6]
            else:
                query = info
            try:
                atr = cls.set_urlencoded(query, extended)
            except Exception:
                atr = ErrorResponse.set_urlencoded(query, extended)
        else:
            raise Exception("Unknown package format: '%s'" %  format)
        assert atr.verify()

        if isinstance(atr, cls):
            self.set_from_access_token(atr)
            if self.access_token.expires_in:
                self.token_expiration_time = time.time() + self.access_token.expires_in
                
        return atr

    def get_access_token_refresh(self, ratr=RefreshAccessTokenRequest,
                                 **kwargs):

        kwargs["refresh_token"] = self.access_token.refresh_token
        ar_args = self._parse_args(ratr, **kwargs)

        return ratr(**ar_args)

    def do_authorization_request(self, cls=AuthorizationRequest,
                                 method="GET", **kwargs):
        """
        Send an AuthorizationRequest

        :param method: The HTTP method to use (GET or POST)
        :return: The HTTP response
        """

        uri = self._endpoint("authorization_endpoint", **kwargs)

        ar = self.get_authorization_request(cls, **kwargs)

        path = uri + '?' + ar.get_urlencoded()

        h_args = dict([(k, v) for k,v in kwargs.items() if k in HTTP_ARGS])

        return self.http.request(path, method, **h_args)

    def do_access_token_request(self, reqcls=AccessTokenRequest,
                                respcls=AccessTokenResponse,
                                method="POST", auth_method="basic",
                                **kwargs):
        """
        Send an AccesstokenRequest.
        Some kind of client authentication needs to be used.

        :param reqcls: Which class to use for creating the request
        :param respcls: Which class to use when parsing the response
        :param method: Which HTTP method to use for sending the request
        :return: A parsed and for standard adherence verified response
        """

        passwd = ""
        if auth_method == "basic":
            # There must be a client_password among the
            # kwargs

            passwd = kwargs["client_password"]
            del kwargs["client_password"]

            self.http.add_credentials(self.client_id, passwd)
        elif auth_method == "request_body":
            kwargs["client_id"] = self.client_id
            assert "client_secret" in kwargs

        atr = self.get_access_token_request(reqcls, **kwargs)

        uri = self._endpoint("token_endpoint", **kwargs)

        h_args = dict([(k, v) for k,v in kwargs.items() if k in HTTP_ARGS])
        if "headers" in h_args:
            h_args["headers"]["content-type"] = DEFAULT_POST_CONTENT_TYPE
        else:
            h_args["headers"] = {"content-type": DEFAULT_POST_CONTENT_TYPE}

        # to please the syntax checker
        response = content = ""
        
        try:
            response, content = self.http.request(uri, method,
                                                    body=atr.get_urlencoded(),
                                                    **h_args)
        except MissingRequiredAttribute:
            raise
        finally:
            if passwd:
                self.http.clear_credentials()

        if response.status == 200:
            assert "application/json" in response["content-type"]
        elif response.status == 500:
            raise Exception("ERROR: Something went wrong: %s" % content)
        else:
            raise Exception("ERROR: Something went wrong [%s]" % response.status)

        return self.parse_access_token_response(respcls, info=content,
                                                  extended=True)


    def _access_token_refresh(self, reqcls, method="POST", **kwargs):

        kwargs["refresh_token"] = self.access_token.refresh_token
            
        atr = self.get_access_token_refresh(reqcls, **kwargs)

        uri = self._endpoint("token_endpoint", **kwargs)

        h_args = dict([(k, v) for k,v in kwargs.items() if k in HTTP_ARGS])
        if "headers" in h_args:
            h_args["headers"]["content-type"] = DEFAULT_POST_CONTENT_TYPE
        else:
            h_args["headers"] = {"content-type": DEFAULT_POST_CONTENT_TYPE}

        return self.http.request(uri, method,
                                 body=atr.get_urlencoded(),
                                 **h_args)

    def do_access_token_refresh(self, reqcls=RefreshAccessTokenRequest,
                                respcls=AccessTokenResponse,
                                method="POST", **kwargs):
        """
        Construct and send a RefreshAccessTokenRequest

        :param reqcls: Which class to use for creating the request
        :param respcls: Which class to use when parsing the response
        :param method: Which HTTP method to use for sending the request
        :return: A parsed and for standard adherence verified response
        """
        response, content = self._access_token_refresh(reqcls, method,
                                                       **kwargs)
        if response.status == 200:
            assert "application/json" in response["content-type"]
        else:
            raise Exception("ERROR: Something went wrong [%s]" % response.status)

        return self.parse_access_token_response(respcls, info=content,
                                                extended=True)

    def fetch_protected_resource(self, uri, method="GET", headers=None,
                                 **kwargs):

        if not self.access_token_is_valid():
            # The token is to old, refresh
            self.do_access_token_refresh()

        if headers is None:
            headers = {}

        try:
            _acc_token = kwargs["access_token"]
            del kwargs["access_token"]
        except KeyError:
            _acc_token= self.access_token

        headers["Authorization"] = "Bearer %s" % base64.encodestring(_acc_token)

        return self.http.request(uri, method, headers=headers, **kwargs)

    def revocate_token(self, method="POST", **kwargs):

        atr = self.get_access_token_request(TokenRevocationRequest, **kwargs)
        uri = self._endpoint("token_revocation_endpoint", **kwargs)
        h_args = dict([(k, v) for k,v in kwargs.items() if k in HTTP_ARGS])

        response, content = self.http.request(uri, method,
                                              body=atr.get_urlencoded(),
                                              **h_args)

        if response == 200:
            return True
        else:
            raise Exception("ERROR: Something went wrong [%s]" % response.status)


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

    def parse_body_request(self, cls=AccessTokenRequest, body=None):
        req = cls.set_urlencoded(body)
        req.verify()
        return req

    def parse_token_request(self, rcls=AccessTokenRequest, body=None):
        return self.parse_body_request(rcls, body)

    def parse_refresh_token_request(self, rcls=RefreshAccessTokenRequest,
                                    body=None):
        return self.parse_body_request(rcls, body)

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