import urllib
import urlparse
import json
import copy

from oic.utils import jwt
from oic.oauth2 import DEF_SIGN_ALG

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
        for typ, keys in collection[jso[target]].items():
            try:
                comb[typ].extend(keys)
            except KeyError:
                comb[typ] = keys
    except KeyError:
        pass

    return comb

class Message(object):
    def __init__(self, _name_, _schema_, **kwargs):
        self._name = _name_
        self._schema = copy.deepcopy(_schema_)
        self._dict = {}
        self.lax = False
        try:
            self.set_defaults(_schema_["default"])
        except KeyError:
            pass

        self.from_dict(kwargs)

    def type(self):
        return self._name

    def parameters(self):
        return self._schema["param"].keys()

    def home(self):
        return self._schema["mod"]

    def set_defaults(self, defaults):
        for key, val in defaults.items():
            self._dict[key] = val

    def to_urlencoded(self):
        """
        Creates a string using the application/x-www-form-urlencoded format

        :return: A string of the application/x-www-form-urlencoded format
        """

        _spec = self._schema["param"]
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
                params.append((key, str(val)))
            elif isinstance(val, list):
                if _ser:
                    params.append((key, str(_ser(val, format="urlencoded"))))
                else:
                    for item in val:
                        params.append((key, str(item)))
            elif isinstance(val, Message):
                params.append((key, str(_ser(val, format="urlencoded"))))
            else:
                try:
                    params.append((key, _ser(val)))
                except Exception:
                    params.append((key, str(val)))

        return urllib.urlencode(params)

    def serialize(self, method="urlencoded", **kwargs):
        return getattr(self, "to_%s" % method)(**kwargs)

    def deserialize(self, info, method="urlencoded", **kwargs):
        try:
            return getattr(self, "from_%s" % method)(info, **kwargs)
        except AttributeError, err:
            raise Exception("Unknown method (%s)" % err)

    def from_urlencoded(self, urlencoded):
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

        _spec = self._schema["param"]

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

    def to_dict(self):
        """
        Return a dictionary representation of the class

        :return: A dict
        """
        _res= {}
        for key, val in self._dict.items():
            if isinstance(val, Message):
                _res[key] = val.to_dict()
            elif isinstance(val, list) and isinstance(val[0], Message):
                _res[key] = [v.to_dict() for v in val]
            else:
                _res[key] = val

        return _res

    def to_json(self):
        """
        Return a JSON representation of the class instance

        :return: A JSON encoded string
        """

        return json.dumps(self._dict)

    def from_dict(self, dictionary):
        """
        Direct translation so the value for one key might be a list or a
        single value.

        :param dictionary: The info
        :return: A class instance or raise an exception on error
        """

        _spec = self._schema["param"]

        for key, val in dictionary.items():
            # Earlier versions of python don't like unicode strings as
            # variable names
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
                        val = [vtype(**dict([(str(x),
                                       y) for x,y
                                          in v.items()])) for v in val]
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

    def to_json(self):
        return json.dumps(self.to_dict())

    def from_json(self, txt):
        return self.from_dict(json.loads(txt))

    def to_jwt(self, key=None, algorithm=""):
        """
        Create a signed JWT representation of the class instance
        draft-jones-json-web-signature-02

        :param key: The signing key
        :param algorithm: The signature algorithm to use
        :return: A signed JWT
        """
        if not algorithm:
            algorithm = DEF_SIGN_ALG
        return jwt.sign(self.to_json(), key, algorithm)


    def from_jwt(self, txt, key, verify=True):
        """
        Given a signed JWT, verify its correctness and then create a class
        instance from the content.

        :param txt: The JWT
        :param key: keys that might be used to verify the signature of the JWT
        :param verify: Whether the signature should be verified or not
        :return: A class instance
        """
        try:
            jso = jwt.unpack(txt)[1]
            if isinstance(jso, basestring):
                jso = json.loads(jso)
            if verify:
                try:
                    _keys = key['.']
                except KeyError:
                    _keys = {}

                if "iss" in jso:
                    _keys = gather_keys(_keys, key, jso, "iss")
                if "aud" in jso:
                    _keys = gather_keys(_keys, key, jso, "aud")

                if "iss" not in jso and "aud" not in jso:
                    for owner, _spec in key.items():
                        if owner == ".":
                            continue
                        for typ, keys in _spec.items():
                            try:
                                _keys[typ].extend(keys)
                            except KeyError:
                                _keys[typ] = keys

                jwt.verify(txt, _keys)
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
        _spec = self._schema["param"]
        try:
            _allowed = self._schema["allowed values"]
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
        return "%s?%s" % (location, self.to_urlencoded())

    def __setitem__(self, key, value):
        try:
            (vtyp, req, _, _deser) = self._schema["param"][key]
            self._add_value(str(key), vtyp, key, value, _deser)
        except KeyError:
            self._dict[key] = value

    def set_schema(self, schema):
        self._schema = schema

    def __eq__(self, other):
        if not isinstance(other, Message):
            return False
        if self._name != other._name:
            return False

        if self._dict != other._dict:
            return False

        return True

#    def __getattr__(self, item):
#        return self._dict[item]

    def __delitem__(self, key):
        del self._dict[key]

# =============================================================================
#

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

SINGLE_REQUIRED_STRING = (basestring, True, None, None)
SINGLE_OPTIONAL_STRING = (basestring, False, None, None)
SINGLE_OPTIONAL_INT = (int, False, None, None)
OPTIONAL_LIST_OF_STRINGS = ([basestring], False, sp_sep_list_serializer,
                                          sp_sep_list_deserializer)
REQUIRED_LIST_OF_STRINGS = ([basestring], True,
                                          sp_sep_list_serializer,
                                          sp_sep_list_deserializer)
SINGLE_OPTIONAL_JSON = (basestring, False, json_serializer, json_deserializer)

#
# =============================================================================
#

SCHEMA = {
    "": {"param": {}},
    "ErrorResponse": {
        "param": {
            "error": SINGLE_REQUIRED_STRING,
            "error_description": SINGLE_OPTIONAL_STRING,
            "error_uri":SINGLE_OPTIONAL_STRING,
        },
    },
    "AuthorizationErrorResponse": {
        "param": {
            "state":SINGLE_OPTIONAL_STRING,
        },
        "parent": ["ErrorResponse"],
        "allowed_values": {
            "error": ["invalid_request", "unathorized_client",
                      "access_denied", "unsupported_response_type",
                      "invalid_scope", "server_error",
                      "temporarily_unavailable"]
        }
    },
    "TokenErrorResponse": {
        "param": {},
        "parent": ["ErrorResponse"],
        "allowed_values": {
            "error": ["invalid_request", "invalid_client",
                      "invalid_grant", "unauthorized_client",
                      "unsupported_grant_type", "invalid_scope"]
        }
    },
    "AccessTokenRequest": {
        "param":{
            "grant_type": SINGLE_REQUIRED_STRING,
            "code": SINGLE_REQUIRED_STRING,
            "redirect_uri": SINGLE_REQUIRED_STRING,
            "client_id": SINGLE_OPTIONAL_STRING,
            "client_secret": SINGLE_OPTIONAL_STRING,
        },
        "default": {"grant_type":"authorization_code"}
    },
    "AuthorizationRequest": {
        "param": {
            "response_type": REQUIRED_LIST_OF_STRINGS,
            "client_id": SINGLE_REQUIRED_STRING,
            "redirect_uri": SINGLE_OPTIONAL_STRING,
            "scope": OPTIONAL_LIST_OF_STRINGS,
            "state": SINGLE_OPTIONAL_STRING
        }
    },
    "AuthorizationResponse": {
        "param": {
            "code": SINGLE_REQUIRED_STRING,
            "state": SINGLE_OPTIONAL_STRING
        }
    },
    "AccessTokenResponse": {
        "param": {
            "access_token": SINGLE_REQUIRED_STRING,
            "token_type": SINGLE_REQUIRED_STRING,
            "expires_in": SINGLE_OPTIONAL_INT,
            "refresh_token": SINGLE_OPTIONAL_STRING,
            "scope": OPTIONAL_LIST_OF_STRINGS,
            "state": SINGLE_OPTIONAL_STRING
        }
    },
    "NoneResponse": {
        "param": {
            "state": SINGLE_OPTIONAL_STRING
        }
    },
    "ROPCAccessTokenRequest": {
        "param": {
            "grant_type": SINGLE_REQUIRED_STRING,
            "username": SINGLE_OPTIONAL_STRING,
            "password": SINGLE_OPTIONAL_STRING,
            "scope": SINGLE_OPTIONAL_STRING
        },
    },
    "CCAccessTokenRequest": {
        "param": {
            "grant_type": SINGLE_REQUIRED_STRING,
            "scope": SINGLE_OPTIONAL_STRING
        },
        "allowed_values": {"grant_type":"client_credentials"},
        "default": {"grant_type":"client_credentials"}
    },
    "RefreshAccessTokenRequest": {
        "param": {
            "grant_type": SINGLE_REQUIRED_STRING,
            "refresh_token": SINGLE_REQUIRED_STRING,
            "client_id": SINGLE_REQUIRED_STRING,
            "scope": SINGLE_OPTIONAL_STRING,
            "client_secret": SINGLE_OPTIONAL_STRING
        },
        "allowed_values": {"grant_type":"refresh_token"},
        "default": {"grant_type":"refresh_token"}
    },
    "TokenRevocationRequest": {
        "param": {
            "token": SINGLE_REQUIRED_STRING,
        }
    },
    "ResourceRequest": {
        "param": {
            "access_token": SINGLE_OPTIONAL_STRING,
        }
    },
}

lc_types = dict((x.lower(), x) for x in SCHEMA.keys())

def join(dic0, dic1):
    res = {}
    for key, val in dic0.items():
        if key not in dic1:
            res[key] = val
        else:
            if isinstance(val, dict):
                res[key] = join(val, dic1[key])
            else:
                val.extend(dic1[key])
                res[key] = val

    for key, val in dic1.items():
        if key in dic0:
            continue
        else:
            res[key] = val

    return res

def join_spec(*arg):
    _child = arg[0]
    _parent = arg[1]
    _sp = {"param": _child["param"].copy()}

    try:
        _parent = inherit(_parent, _parent["parent"])
    except KeyError:
        pass

    # param
    for key, val in _parent["param"].items():
        # Child overrides parent
        if key not in _sp["param"]:
            _sp["param"][key] = val

    # allowed values
    _av = [None, None]
    for i in [0,1]:
        try:
            _av[i] = arg[i]["allowed_values"]
        except KeyError:
            pass

    if _av[0] is None and _av[1] is None:
        pass
    elif _av[0] is None:
        if _av[1]:
            _sp["allowed_values"] = _av[1]
    elif _av[1] is None:
        if _av[0]:
            _sp["allowed_values"] = _av[0]
    else:
        _sp["allowed_values"] = join(_av[1], _av[0])

    # default
    if "default" in _child:
        _def = _child["default"]
        if "default" in _parent:
            for key, val in _parent["default"].items():
                if key not in _def:
                    _def[key] = val
        _sp["default"] = _def
    else:
        try:
            _sp["default"] = _parent["default"]
        except KeyError:
            pass

    # verify
    try:
        _sp["verify"] = _child["verify"]
    except KeyError:
        try:
            _sp["verify"] = _parent["verify"]
        except KeyError:
            pass

    return _sp

def inherit(spec, parent):
    for p in parent:
        if isinstance(p, dict):
            _spec = p
        else:
            _spec = SCHEMA[p]
        spec = join_spec(spec, _spec)

    return spec

_schema = {}
for key, _spec in SCHEMA.items():
    if "parent" in _spec:
        _schema[key] = inherit(_spec, _spec["parent"])
    else:
        _schema[key] = _spec
    _schema[key]["mod"] = __name__
    _schema[key]["name"] = key

SCHEMA = _schema

def by_schema(_spec_, **kwargs):
    try:
        if isinstance(_spec_, basestring):
            name = lc_types[_spec_.lower()]
            pkeys = SCHEMA[name]["param"].keys()
        else:
            pkeys = _spec_["param"].keys()

        return dict([(k,v) for k, v in kwargs.items() if k in pkeys])
    except KeyError:
        raise Exception("Unknown message type")

def add_non_standard(msg1, msg2):
    """
    Adds all non standard attributes in msg1 to msg2
    """
    for key, val in msg1.items():
        if key not in msg1._schema["param"]:
            msg2[key] = val

def message(_type_, **kwargs):
    try:
        name = lc_types[_type_.lower()]
        return Message(name, SCHEMA[name], **kwargs)
    except KeyError:
        raise Exception("Unknown message type")

def message_from_schema(schema, **kwargs):
    return Message(schema["name"], schema, **kwargs)

def msg_deser(val, format, typ="", schema=None, **kwargs):
    if typ:
        return message(typ).deserialize(val, format, **kwargs)
    else:
        return Message(schema["name"], schema).deserialize(val, format,
                                                           **kwargs)

if __name__ == "__main__":
    foo = Message("AccessTokenRequest", SCHEMA["AccessTokenRequest"],
                  grant_type="authorization_code",
                  code="foo", redirect_uri="http://example.com/cb")
    print foo
    bar = Message("CCAccessTokenRequest",SCHEMA["CCAccessTokenRequest"],
                  grant_type="client_credentials")
    print bar
    print bar.verify()
    xyz = Message("AuthorizationErrorResponse",
                  SCHEMA["AuthorizationErrorResponse"],
                  error="invalid_request",
                  state="foxbar")
    print xyz
    print xyz.verify()

    urlencoded = foo.to_urlencoded()
    atr = Message("AccessTokenRequest",
                  SCHEMA["AccessTokenRequest"]).from_urlencoded(urlencoded)
    print atr

    atr = Message("AccessTokenRequest",
                  SCHEMA["AccessTokenRequest"]).deserialize(urlencoded)
    print atr

    atr = message("AccessTokenRequest").deserialize(urlencoded)
    print atr

    areq = message("accesstokenrequest", grant_type="authorization_code",
                  code="foo", redirect_uri="http://example.com/cb")
    print areq
