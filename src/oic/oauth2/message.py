#!/usr/bin/env python
#
__author__ = 'rohe0002'

import urllib
import urlparse
import json
from oic.utils import jwt
from oic.oauth2 import DEF_SIGN_ALG

Version = "2.0"

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

ERRTXT = "On '%s': %s"

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
                elif isinstance(val, Base):
                    params.append((attribute, str(_ser(val,
                                                       format="urlencoded",
                                                       extended=extended))))
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
    def from_dictionary(cls, dictionary, extended=False):
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

        for key, val in dictionary.items():
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
                            try:
                                val = _deser(val, format="dict",
                                             extended=extended)
                            except Exception, exc:
                                raise DecodeError(ERRTXT % (key, exc))

                        if issubclass(vtype, Base):
                            try:
                                args[skey] = [
                                    vtype(**dict([(str(x),
                                               y) for x,y
                                                  in v.items()])) for v in val]
                            except Exception, exc:
                                raise DecodeError(ERRTXT % (key, exc))
                        else:
                            for v in val:
                                if not isinstance(v, vtype):
                                    raise DecodeError(ERRTXT % (key,
                                                        "type != %s" % vtype))

                            args[skey] = val
                    else:
                        raise DecodeError(ERRTXT % (key, "type != %s" % vtype))
                else:
                    if isinstance(val,vtyp): # Not necessary to do anything
                        args[skey] = val
                    else:
                        if _deser:
                            try:
                                val = _deser(val, format="dict",
                                             extended=extended)
                            except Exception, exc:
                                raise DecodeError(ERRTXT % (key, exc))

                        if isinstance(val, basestring):
                            args[skey] = val
                        elif isinstance(val, list):
                            if len(val) == 1:
                                args[skey] = val[0]
                            else:
                                raise TooManyValues(key)
                        else:
                            args[skey] = val
            elif extended:
                extension[skey] = val
            #ignore attributes I don't know about

        if extended and extension:
            args.update(extension)

        return cls(**args)

    @classmethod
    def set_json(cls, txt, extended=False):
        return cls.from_dictionary(json.loads(txt), extended)

    @classmethod
    def from_json(cls, txt, extended=False):
        return cls.from_dictionary(json.loads(txt), extended)

    def to_json(self, extended=False):
        return self.get_json(extended)


    def get_jwt(self, extended=False, key=None, algorithm=""):
        """
        Create a signed JWT representation of the class instance
        draft-jones-json-web-signature-02

        :param extended: Whether parameter extension should be allowed
        :param key: The signing key
        :param algorithm: The signature algorithm to use
        :return: A signed JWT
        """
        if not algorithm:
            algorithm = DEF_SIGN_ALG
        return jwt.sign(self.get_json(extended), key, algorithm)

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
        try:
            if verify:
                jso = jwt.verify(txt, key)
            else:
                jso = jwt.unpack(txt)[1]
        except Exception:
            raise

        if isinstance(jso, basestring):
            jso = json.loads(jso)
        return cls.from_dictionary(jso, extended)

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

    def verify(self, **kwargs):
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

    def __contains__(self, item):
        try:
            if getattr(self, item):
                return True
            else:
                return False
        except Exception:
            pass
        
        return item in self.c_extension

    def request(self, location):
        return "%s?%s" % (location, self.to_urlencoded(extended=True))
    
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

    def verify(self, **kwargs):
        if self.error:
            if self.error in ["invalid_request", "unathorized_client",
                              "access_denied", "unsupported_response_type",
                              "invalid_scope", "server_error",
                              "temporarily_unavailable"]:
                pass
            else:
                raise ValueError("'%s' not an valid error type" % self.error)

        return ErrorResponse.verify(self, **kwargs)

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

    def verify(self, **kwargs):
        if self.error:
            if not self.error in ["invalid_request", "invalid_client",
                              "invalid_grant", "unauthorized_client",
                              "unsupported_grant_type", "invalid_scope"]:
                raise ValueError("'%s' not an valid error type" % self.error)

        return ErrorResponse.verify(self, **kwargs)

class AccessTokenResponse(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["access_token"] = SINGLE_REQUIRED_STRING
    c_attributes["token_type"] = SINGLE_REQUIRED_STRING
    c_attributes["expires_in"] = SINGLE_OPTIONAL_INT
    c_attributes["refresh_token"] = SINGLE_OPTIONAL_STRING
    c_attributes["scope"] = OPTIONAL_LIST_OF_STRINGS
    # Only for implicit flow
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
    c_attributes["client_id"] = SINGLE_OPTIONAL_STRING
    c_attributes["client_secret"] = SINGLE_OPTIONAL_STRING

    def __init__(self, grant_type="authorization_code",
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

class NoneResponse(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["state"] = SINGLE_OPTIONAL_STRING

    def __init__(self, state=None, **kwargs):
        Base.__init__(self, **kwargs)
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

    def verify(self, **kwargs):
        assert self.grant_type == "password"
        return Base.verify(self, **kwargs)

class CCAccessTokenRequest(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["grant_type"] = SINGLE_REQUIRED_STRING
    c_attributes["scope"] = SINGLE_OPTIONAL_STRING

    def __init__(self, grant_type="client_credentials", scope=None, **kwargs):
        Base.__init__(self,**kwargs)
        self.grant_type = grant_type
        self.scope = scope

    def verify(self, **kwargs):
        assert self.grant_type == "client_credentials"
        return Base.verify(self, **kwargs)

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

    def verify(self, **kwargs):
        assert self.grant_type == "refresh_token"
        return Base.verify(self, **kwargs)


class TokenRevocationRequest(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["token"] = SINGLE_REQUIRED_STRING

    def __init__(self, token=None, **kwargs):
        Base.__init__(self, **kwargs)
        self.token = token

class ResourceRequest(Base):
    c_attributes = Base.c_attributes.copy()
    c_attributes["access_token"] = SINGLE_OPTIONAL_STRING

    def __init__(self, access_token=None, **kwargs):
        Base.__init__(self, **kwargs)
        self.access_token = access_token

def factory(cls, **argv):
    _dict = {}
    for attr in cls.c_attributes:
        try:
            _dict[attr] = argv[attr]
        except KeyError:
            pass

    return cls(**_dict)

