import logging
import urllib
import urlparse
import json

from jwkest import jws
from jwkest import jwe
from jwkest import b64d
#from oic.oauth2 import DEF_SIGN_ALG
import jwkest

logger = logging.getLogger(__name__)

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

ERRTXT = "On '%s': %s"

def gather_keys(comb, collection, jso, target):
    try:
        _id = jso[target]
    except KeyError:
        return comb

    try:
        _col = collection[_id]
    except KeyError:
        if _id.endswith("/"):
            _id = _id[:-1]
            try:
                _col = collection[_id]
            except KeyError:
                return comb
        else:
            return comb

    try:
        for typ, keys in _col.items():
            try:
                comb[typ].update(keys)
            except KeyError:
                comb[typ] = keys
    except KeyError:
        pass

    return comb

def swap_dict(dic):
    return dict([(val, key) for key, val in dic.items()])

class Message(object):
    c_param = {}
    c_default = {}
    c_allowed_values = {}

    def __init__(self, **kwargs):
        self._dict = self.c_default.copy()
        self.lax = False
        self.from_dict(kwargs)

    def type(self):
        return self.__class__.__name__

    def parameters(self):
        return self.c_param.keys()

    def set_defaults(self):
        for key, val in self.c_default.items():
            self._dict[key] = val

    def to_urlencoded(self, lev=0):
        """
        Creates a string using the application/x-www-form-urlencoded format

        :return: A string of the application/x-www-form-urlencoded format
        """

        _spec = self.c_param
        if not self.lax:
            for attribute, (_, req, _ser, _) in _spec.items():
                if req and attribute not in self._dict:
                    raise MissingRequiredAttribute("%s" % attribute)

        params = []

        for key, val in self._dict.items():
            try:
                (_, req, _ser, _) = _spec[key]
            except KeyError: #extra attribute
                try:
                    (_, req, _ser, _) = _spec['*']
                except KeyError:
                    _ser = None

            # Should I allow parameters with "" as value ???
            if isinstance(val, basestring):
                params.append((key, unicode(val)))
            elif isinstance(val, list):
                if _ser:
                    params.append((key, str(_ser(val, format="urlencoded",
                                                 lev=lev))))
                else:
                    for item in val:
                        params.append((key, str(item)))
            elif isinstance(val, Message):
                params.append((key, str(_ser(val, format="urlencoded",
                                             lev=lev))))
            else:
                try:
                    params.append((key, _ser(val, lev=lev)))
                except Exception, err:
                    params.append((key, str(val)))

        try:
            return urllib.urlencode(params)
        except UnicodeEncodeError:
            _val = [(k,unicode.encode(v, "utf-8")) for k,v in params]
            return urllib.urlencode(_val)

    def serialize(self, method="urlencoded", lev=0, **kwargs):
        return getattr(self, "to_%s" % method)(lev=lev, **kwargs)

    def deserialize(self, info, method="urlencoded", **kwargs):
        try:
            return getattr(self, "from_%s" % method)(info, **kwargs)
        except AttributeError, err:
            raise Exception("Unknown method (%s)" % err)

    def from_urlencoded(self, urlencoded, **kwargs):
        """
        from a string of the application/x-www-form-urlencoded format creates
        a class instance

        :param urlencoded: The string
        :return: An instance of the cls class
        """

        #parse_qs returns a dictionary with keys and values. The values are
        #always lists even if there is only one value in the list.
        #keys only appears once.

        if isinstance(urlencoded, basestring):
            pass
        elif isinstance(urlencoded, list):
            urlencoded = urlencoded[0]

        _spec = self.c_param

        for key, val in urlparse.parse_qs(urlencoded).items():
            try:
                (typ, _, _, _deser) = _spec[key]
            except KeyError:
                try:
                    (typ, _, _, _deser) = _spec['*']
                except KeyError:
                    if len(val) == 1:
                        val = val[0]

                    self._dict[key] = val
                    continue

            if isinstance(typ, list):
                if _deser:
                    self._dict[key] = _deser(val[0], "urlencoded")
                else:
                    self._dict[key] = val
            else: # must be single value
                if len(val) == 1:
                    if _deser:
                        self._dict[key] = _deser(val[0], "urlencoded")
                    elif isinstance(val[0], typ):
                        self._dict[key] = val[0]
                    else:
                        try:
                            self._dict[key] = typ(val[0])
                        except :
                            raise ValueError
                else:
                    raise TooManyValues

        return self

    def to_dict(self, lev=0):
        """
        Return a dictionary representation of the class

        :return: A dict
        """

        _spec = self.c_param

        _res= {}
        lev += 1
        for key, val in self._dict.items():
            try:
                (vtyp, req, _ser, _) = _spec[str(key)]
            except KeyError:
                _ser = None

            if _ser:
                val = _ser(val, "json", lev)

            if isinstance(val, Message):
                _res[key] = val.to_dict(lev)
            elif isinstance(val, list) and isinstance(val[0], Message):
                _res[key] = [v.to_dict(lev) for v in val]
            else:
                _res[key] = val

        return _res

    def from_dict(self, dictionary):
        """
        Direct translation so the value for one key might be a list or a
        single value.

        :param dictionary: The info
        :return: A class instance or raise an exception on error
        """

        _spec = self.c_param

        for key, val in dictionary.items():
            # Earlier versions of python don't like unicode strings as
            # variable names
            if val == "" or val == [""]:
                continue

            skey = str(key)
            try:

                (vtyp, req, _, _deser) = _spec[key]
            except KeyError:
                try:
                    (vtyp, _, _, _deser) = _spec['*']
                    if val is None:
                        self._dict[key] = val
                        continue
                except KeyError:
                    self._dict[key] = val
                    continue

            self._add_value(skey, vtyp, key, val, _deser)
        return self

    def _add_value(self, skey, vtyp, key, val, _deser):
#        if not val:
#            return

        if isinstance(val, list):
            if len(val) == 0 or val[0] is None:
                return

        if isinstance(vtyp, list):
            vtype = vtyp[0]
            if isinstance(val, vtype):
                if _deser:
                    try:
                        self._dict[skey] = _deser(val, format="urlencoded")
                    except Exception, exc:
                        raise DecodeError(ERRTXT % (key, exc))
                else:
                    setattr(self, skey, [val])
            elif isinstance(val, list):
                if _deser:
                    try:
                        val = _deser(val, format="dict")
                    except Exception, exc:
                        raise DecodeError(ERRTXT % (key, exc))

                if issubclass(vtype, Message):
                    try:
                        _val = []
                        for v in val:
                            _val.append(vtype(**dict([(str(x),y) for x,
                                                            y in v.items()])))
                        val = _val
                    except Exception, exc:
                        raise DecodeError(ERRTXT % (key, exc))
                else:
                    for v in val:
                        if not isinstance(v, vtype):
                            raise DecodeError(ERRTXT % (key,
                                                        "type != %s" % vtype))

                self._dict[skey] = val
            else:
                raise DecodeError(ERRTXT % (key, "type != %s" % vtype))
        else:
            if isinstance(val,vtyp): # Not necessary to do anything
                self._dict[skey] = val
            else:
                if _deser:
                    try:
                        val = _deser(val, format="dict")
                    except Exception, exc:
                        raise DecodeError(ERRTXT % (key, exc))

                if isinstance(val, basestring):
                    self._dict[skey] = val
                elif isinstance(val, list):
                    if len(val) == 1:
                        self._dict[skey] = val[0]
                    elif not len(val):
                        pass # ignore
                    else:
                        raise TooManyValues(key)
                else:
                    self._dict[skey] = val

    def to_json(self, lev=0):
        if lev:
            return self.to_dict(lev+1)
        else:
            return json.dumps(self.to_dict(lev+1))

    def from_json(self, txt, **kwargs):
        return self.from_dict(json.loads(txt))

    def to_jwt(self, key=None, algorithm="", lev=0):
        """
        Create a signed JWT representation of the class instance

        :param key: The signing key
        :param algorithm: The signature algorithm to use
        :return: A signed JWT
        """

        if algorithm:
            return jws.sign(self.to_json(lev), key, algorithm)
        else:
            return jwkest.pack(self.to_json(lev))


    def from_jwt(self, txt, key=None, verify=True, keystore=None, **kwargs):
        """
        Given a signed and/or encrypted JWT, verify its correctness and then
        create a class instance from the content.

        :param txt: The JWT
        :param key: keys that might be used to decrypt and/or verify the
            signature of the JWT
        :param verify: Whether the signature should be verified or not
        :return: A class instance
        """
        if key == None and keystore is not None:
            key = keystore.get_verify_key(owner=".")
        else:
            key = {}

        header = json.loads(b64d(str(txt.split(".")[0])))
        try:
            type = header["typ"]
        except KeyError:
            type = None

        jso = None
        if type == "JWE" or ("alg" in header and "enc" in header): # encrypted
            if keystore:
                dkeys = keystore.get_decrypt_key(owner=".")
            else:
                dkeys = {}
            txt = jwe.decrypt(txt, dkeys, "private")
            try:
                jso = json.loads(txt)
            except Exception:
                pass
            #type = self._typ(txt)

        # assume type == 'JWS'
        if not jso:
            try:
                jso = jwkest.unpack(txt)[1]
                if isinstance(jso, basestring):
                    jso = json.loads(jso)
                if verify:
                    if keystore:
                        for ent in ["iss", "aud", "client_id"]:
                            try:
                                for t, vs in keystore.get_verify_key(
                                                        owner=jso[ent]).items():
                                    try:
                                        key[t].extend(vs)
                                    except KeyError:
                                        key[t] = vs
                            except KeyError:
                                pass

                    jws.verify(txt, key)
            except Exception:
                raise

        return self.from_dict(jso)

    def __str__(self):
        return self.to_urlencoded()

    #noinspection PyUnusedLocal
    def verify(self, **kwargs):
        """
        Make sure all the required values are there and that the values are
        of the correct type
        """
        _spec = self.c_param
        try:
            _allowed = self.c_allowed_values
        except KeyError:
            _allowed = {}

        for (attribute, (typ, required, _, _)) in _spec.items():
            if attribute == "*":
                continue

            try:
                val = self._dict[attribute]
            except KeyError:
                if required:
                    raise MissingRequiredAttribute("%s" % attribute)
                continue

            if attribute not in _allowed:
                continue

            if typ is basestring:
                if val not in _allowed[attribute]:
                    raise ValueError("Not allowed value '%s'" % val)
            elif typ is int:
                if val not in _allowed[attribute]:
                    raise ValueError("Not allowed value '%s'" % val)
            elif isinstance(typ, list):
                if isinstance(val, list): #
                    _typ = typ[0]
                    for item in val:
                        if item not in _allowed[attribute]:
                            raise ValueError("Not allowed value '%s'" % val)

        return True


    def keys(self):
        """
        Return a list of attribute/keys/parameters of this class that has
        values.

        :return: A list of attribute names
        """
        return self._dict.keys()

    def __getitem__(self, item):
        return self._dict[item]

    def items(self):
        return self._dict.items()

    def __contains__(self, item):
        return item in self._dict

    def request(self, location):
        if "?" in location:
            return "%s&%s" % (location, self.to_urlencoded())
        else:
            return "%s?%s" % (location, self.to_urlencoded())

    def __setitem__(self, key, value):
        try:
            (vtyp, req, _, _deser) = self.c_param[key]
            self._add_value(str(key), vtyp, key, value, _deser)
        except KeyError:
            self._dict[key] = value

    def __eq__(self, other):
        if not isinstance(other, Message):
            return False
        if self.type() != other.type():
            return False

        if self._dict != other._dict:
            return False

        return True

#    def __getattr__(self, item):
#        return self._dict[item]

    def __delitem__(self, key):
        del self._dict[key]

    def extra(self):
        return dict([(key,val) for key,
                         val in self._dict.items() if key not in self.c_param])

# =============================================================================


def by_schema(cls, **kwa):
    return dict([(key, val) for key,val in kwa.items() if key in cls.c_param])

def add_non_standard(msg1, msg2):
    for key, val in msg2.extra():
        if key not in msg1.c_param:
            msg1[key] = val

# =============================================================================

#noinspection PyUnusedLocal
def list_serializer(vals, format="urlencoded", lev=0):
    if format == "urlencoded":
        return " ".join(vals)
    else:
        return vals

#noinspection PyUnusedLocal
def list_deserializer(val, format="urlencoded"):
    if format == "urlencoded":
        if isinstance(val, basestring):
            return val.split(" ")
        elif isinstance(val, list) and len(val) == 1:
            return val[0].split(" ")
    else:
        return val

#noinspection PyUnusedLocal
def sp_sep_list_serializer(vals, format="urlencoded", lev=0):
    if isinstance(vals, basestring):
        return vals
    else:
        return " ".join(vals)

#noinspection PyUnusedLocal
def sp_sep_list_deserializer(val, format="urlencoded"):
    if isinstance(val, basestring):
        return val.split(" ")
    elif isinstance(val, list) and len(val) == 1:
        return val[0].split(" ")
    else:
        return val

#noinspection PyUnusedLocal
def json_serializer(obj, format="urlencoded", lev=0):
    return json.dumps(obj)

#noinspection PyUnusedLocal
def json_deserializer(txt, format="urlencoded"):
    return json.loads(txt)

SINGLE_REQUIRED_STRING = (basestring, True, None, None)
SINGLE_OPTIONAL_STRING = (basestring, False, None, None)
SINGLE_OPTIONAL_INT = (int, False, None, None)
OPTIONAL_LIST_OF_STRINGS = ([basestring], False, list_serializer,
                                          list_deserializer)
REQUIRED_LIST_OF_STRINGS = ([basestring], True, list_serializer,
                                          list_deserializer)
OPTIONAL_LIST_OF_SP_SEP_STRINGS = ([basestring], False, sp_sep_list_serializer,
                                          sp_sep_list_deserializer)
REQUIRED_LIST_OF_SP_SEP_STRINGS = ([basestring], True,
                                          sp_sep_list_serializer,
                                          sp_sep_list_deserializer)
SINGLE_OPTIONAL_JSON = (basestring, False, json_serializer, json_deserializer)

#
# =============================================================================
#

class ErrorResponse(Message):
    c_param = {"error": SINGLE_REQUIRED_STRING,
             "error_description": SINGLE_OPTIONAL_STRING,
             "error_uri":SINGLE_OPTIONAL_STRING,
    }

class AuthorizationErrorResponse(ErrorResponse):
    c_param = ErrorResponse.c_param.copy()
    c_param.update({"state":SINGLE_OPTIONAL_STRING})
    c_allowed_values = ErrorResponse.c_allowed_values.copy()
    c_allowed_values.update({"error":["invalid_request",
                                 "unathorized_client",
                                 "access_denied",
                                 "unsupported_response_type",
                                 "invalid_scope", "server_error",
                                 "temporarily_unavailable"]})

class TokenErrorResponse(ErrorResponse):
    c_allowed_values = {"error":["invalid_request", "invalid_client",
                                 "invalid_grant", "unauthorized_client",
                                 "unsupported_grant_type",
                                 "invalid_scope"]}

class AccessTokenRequest(Message):
    c_param = {"grant_type": SINGLE_REQUIRED_STRING,
               "code": SINGLE_REQUIRED_STRING,
               "redirect_uri": SINGLE_REQUIRED_STRING,
               "client_id": SINGLE_OPTIONAL_STRING,
               "client_secret": SINGLE_OPTIONAL_STRING,}
    c_default = {"grant_type":"authorization_code"}

class AuthorizationRequest(Message):
    c_param = {
        "response_type": REQUIRED_LIST_OF_SP_SEP_STRINGS,
        "client_id": SINGLE_REQUIRED_STRING,
        "redirect_uri": SINGLE_OPTIONAL_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "state": SINGLE_OPTIONAL_STRING
    }

class AuthorizationResponse(Message):
    c_param = {
        "code": SINGLE_REQUIRED_STRING,
        "state": SINGLE_OPTIONAL_STRING
    }

class AccessTokenResponse(Message):
    c_param = {
        "access_token": SINGLE_REQUIRED_STRING,
        "token_type": SINGLE_REQUIRED_STRING,
        "expires_in": SINGLE_OPTIONAL_INT,
        "refresh_token": SINGLE_OPTIONAL_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "state": SINGLE_OPTIONAL_STRING
    }

class NoneResponse(Message):
    c_param = {
        "state": SINGLE_OPTIONAL_STRING
    }

class ROPCAccessTokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "username": SINGLE_OPTIONAL_STRING,
        "password": SINGLE_OPTIONAL_STRING,
        "scope": SINGLE_OPTIONAL_STRING
    }

class CCAccessTokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "scope": SINGLE_OPTIONAL_STRING
    }
    c_default = {"grant_type":"client_credentials"}
    c_allowed_values = {"grant_type": ["client_credentials"]}

class RefreshAccessTokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "refresh_token": SINGLE_REQUIRED_STRING,
        "client_id": SINGLE_REQUIRED_STRING,
        "scope": SINGLE_OPTIONAL_STRING,
        "client_secret": SINGLE_OPTIONAL_STRING
    }
    c_default = {"grant_type":"refresh_token"}
    c_allowed_values = {"grant_type": ["refresh_token"]}

class TokenRevocationRequest(Message):
    c_param = {"token": SINGLE_REQUIRED_STRING}

class ResourceRequest(Message):
    c_param = {"access_token": SINGLE_OPTIONAL_STRING}

MSG = {
    "Message": Message,
    "ErrorResponse": ErrorResponse,
    "AuthorizationErrorResponse": AuthorizationErrorResponse,
    "TokenErrorResponse": TokenErrorResponse,
    "AccessTokenRequest": AccessTokenRequest,
    "AuthorizationRequest": AuthorizationRequest,
    "AuthorizationResponse": AuthorizationResponse,
    "AccessTokenResponse": AccessTokenResponse,
    "NoneResponse": NoneResponse,
    "ROPCAccessTokenRequest": ROPCAccessTokenRequest,
    "CCAccessTokenRequest": CCAccessTokenRequest,
    "RefreshAccessTokenRequest": RefreshAccessTokenRequest,
    "TokenRevocationRequest": TokenRevocationRequest,
    "ResourceRequest": ResourceRequest,
}

def factory(msgtype):
    try:
        return MSG[msgtype]
    except KeyError:
        raise Exception("Unknown message type: %s" % msgtype)

if __name__ == "__main__":
    foo = AccessTokenRequest(grant_type="authorization_code",
                             code="foo",
                             redirect_uri="http://example.com/cb")
    print foo
#    bar = Message("CCAccessTokenRequest",SCHEMA["CCAccessTokenRequest"],
#                  grant_type="client_credentials")
#    print bar
#    print bar.verify()
#    xyz = Message("AuthorizationErrorResponse",
#                  SCHEMA["AuthorizationErrorResponse"],
#                  error="invalid_request",
#                  state="foxbar")
#    print xyz
#    print xyz.verify()
#
#    urlencoded = foo.to_urlencoded()
#    atr = Message("AccessTokenRequest",
#                  SCHEMA["AccessTokenRequest"]).from_urlencoded(urlencoded)
#    print atr
#
#    atr = Message("AccessTokenRequest",
#                  SCHEMA["AccessTokenRequest"]).deserialize(urlencoded)
#    print atr
#
#    atr = message("AccessTokenRequest").deserialize(urlencoded)
#    print atr
#
#    areq = message("accesstokenrequest", grant_type="authorization_code",
#                  code="foo", redirect_uri="http://example.com/cb")
#    print areq
