import copy
import logging
import json

from jwkest import b64d
from jwkest import jwe
from jwkest import jws
from jwkest.jwe import JWE

from jwkest.jwk import keyitems2keyreps

from jwkest.jws import JWS

from jwkest.jwt import JWT
import six

from six.moves.urllib.parse import urlparse, urlencode, parse_qs
from oic.exception import PyoidcError
from oic.exception import MessageException
from past.builtins import basestring

logger = logging.getLogger(__name__)


class FormatError(PyoidcError):
    pass


class MissingRequiredAttribute(MessageException):
    def __init__(self, attr, message=""):
        Exception.__init__(self, attr)
        self.message = message

    def __str__(self):
        return "Missing required attribute '%s'" % self.args[0]


class MissingRequiredValue(MessageException):
    pass


class MissingSigningKey(PyoidcError):
    pass


class TooManyValues(MessageException):
    pass


class DecodeError(MessageException):
    pass


class GrantExpired(PyoidcError):
    pass


class OldAccessToken(PyoidcError):
    pass


class SchemeError(MessageException):
    pass


class ParameterError(MessageException):
    pass


class NotAllowedValue(MessageException):
    pass


class WrongSigningAlgorithm(MessageException):
    pass


class WrongEncryptionAlgorithm(MessageException):
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


def jwt_header(txt):
    return json.loads(b64d(str(txt.split(".")[0])))


class Message(object):
    c_param = {}
    c_default = {}
    c_allowed_values = {}

    def __init__(self, **kwargs):
        self._dict = self.c_default.copy()
        self.lax = False
        self.jws_header = None
        self.jwe_header = None
        self.from_dict(kwargs)
        self.verify_ssl = True

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
            for attribute, (_, req, _ser, _, na) in _spec.items():
                if req and attribute not in self._dict:
                    raise MissingRequiredAttribute("%s" % attribute,
                                                   "%s" % self)

        params = []

        for key, val in self._dict.items():
            try:
                (_, req, _ser, _, null_allowed) = _spec[key]
            except KeyError:  # extra attribute
                try:
                    _key, lang = key.split("#")
                    (_, req, _ser, _deser, null_allowed) = _spec[_key]
                except (ValueError, KeyError):
                    try:
                        (_, req, _ser, _, null_allowed) = _spec['*']
                    except KeyError:
                        _ser = None
                        null_allowed = False

            if val is None and null_allowed is False:
                continue
            elif isinstance(val, six.string_types):
                # Should I allow parameters with "" as value ???
                params.append((key, val.encode("utf-8")))
            elif isinstance(val, list):
                if _ser:
                    params.append((key, str(_ser(val, sformat="urlencoded",
                                                 lev=lev))))
                else:
                    for item in val:
                        params.append((key, str(item).encode('utf-8')))
            elif isinstance(val, Message):
                try:
                    _val = json.dumps(_ser(val, sformat="dict", lev=lev+1))
                    params.append((key, _val))
                except TypeError:
                    params.append((key, val))
            elif val is None:
                params.append((key, val))
            else:
                try:
                    params.append((key, _ser(val, lev=lev)))
                except Exception:
                    params.append((key, str(val)))

        try:
            return urlencode(params)
        except UnicodeEncodeError:
            _val = []
            for k, v in params:
                try:
                    _val.append((k, v.encode("utf-8")))
                except TypeError:
                    _val.append((k, v))
            return urlencode(_val)

    def serialize(self, method="urlencoded", lev=0, **kwargs):
        return getattr(self, "to_%s" % method)(lev=lev, **kwargs)

    def deserialize(self, info, method="urlencoded", **kwargs):
        try:
            func = getattr(self, "from_%s" % method)
        except AttributeError as err:
            raise FormatError("Unknown serialization method (%s)" % method)
        else:
            return func(info, **kwargs)

    def from_urlencoded(self, urlencoded, **kwargs):
        """
        from a string of the application/x-www-form-urlencoded format creates
        a class instance

        :param urlencoded: The string
        :return: An instance of the cls class
        """

        # parse_qs returns a dictionary with keys and values. The values are
        # always lists even if there is only one value in the list.
        # keys only appears once.

        if isinstance(urlencoded, six.string_types):
            pass
        elif isinstance(urlencoded, list):
            urlencoded = urlencoded[0]

        _spec = self.c_param

        for key, val in parse_qs(urlencoded).items():
            try:
                (typ, _, _, _deser, null_allowed) = _spec[key]
            except KeyError:
                try:
                    _key, lang = key.split("#")
                    (typ, _, _, _deser, null_allowed) = _spec[_key]
                except (ValueError, KeyError):
                    try:
                        (typ, _, _, _deser, null_allowed) = _spec['*']
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
            else:  # must be single value
                if len(val) == 1:
                    if _deser:
                        self._dict[key] = _deser(val[0], "urlencoded")
                    elif isinstance(val[0], typ):
                        self._dict[key] = val[0]
                    else:
                        try:
                            self._dict[key] = typ(val[0])
                        except KeyError:
                            raise ParameterError(key)
                else:
                    raise TooManyValues

        return self

    def to_dict(self, lev=0):
        """
        Return a dictionary representation of the class

        :return: A dict
        """

        _spec = self.c_param

        _res = {}
        lev += 1
        for key, val in self._dict.items():
            try:
                (_, req, _ser, _, null_allowed) = _spec[str(key)]
            except KeyError:
                try:
                    _key, lang = key.split("#")
                    (_, req, _ser, _, null_allowed) = _spec[_key]
                except (ValueError, KeyError):
                    try:
                        (_, req, _ser, _, null_allowed) = _spec['*']
                    except KeyError:
                        _ser = None

            if _ser:
                val = _ser(val, "dict", lev)

            if isinstance(val, Message):
                _res[key] = val.to_dict(lev+1)
            elif isinstance(val, list) and isinstance(val[0], Message):
                _res[key] = [v.to_dict(lev) for v in val]
            else:
                _res[key] = val

        return _res

    def from_dict(self, dictionary, **kwargs):
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
                (vtyp, req, _, _deser, null_allowed) = _spec[key]
            except KeyError:
                # might be a parameter with a lang tag
                try:
                    _key, lang = skey.split("#")
                except ValueError:
                    try:
                        (vtyp, _, _, _deser, null_allowed) = _spec['*']
                        if val is None:
                            self._dict[key] = val
                            continue
                    except KeyError:
                        self._dict[key] = val
                        continue
                else:
                    try:
                        (vtyp, req, _, _deser, null_allowed) = _spec[_key]
                    except KeyError:
                        try:
                            (vtyp, _, _, _deser, null_allowed) = _spec['*']
                            if val is None:
                                self._dict[key] = val
                                continue
                        except KeyError:
                            self._dict[key] = val
                            continue

            self._add_value(skey, vtyp, key, val, _deser, null_allowed)
        return self

    def _add_value(self, skey, vtyp, key, val, _deser, null_allowed):
        # if not val:
        # return

        if isinstance(val, list):
            if (len(val) == 0 or val[0] is None) and null_allowed is False:
                return

        if isinstance(vtyp, list):
            vtype = vtyp[0]
            if isinstance(val, vtype):
                if issubclass(vtype, Message):
                    self._dict[skey] = [val]
                elif _deser:
                    try:
                        self._dict[skey] = _deser(val, sformat="urlencoded")
                    except Exception as exc:
                        raise DecodeError(ERRTXT % (key, exc))
                else:
                    setattr(self, skey, [val])
            elif isinstance(val, list):
                if _deser:
                    try:
                        val = _deser(val, sformat="dict")
                    except Exception as exc:
                        raise DecodeError(ERRTXT % (key, exc))

                if issubclass(vtype, Message):
                    try:
                        _val = []
                        for v in val:
                            _val.append(vtype(**dict([(str(x), y) for x, y
                                                      in v.items()])))
                        val = _val
                    except Exception as exc:
                        raise DecodeError(ERRTXT % (key, exc))
                else:
                    for v in val:
                        if not isinstance(v, vtype):
                            raise DecodeError(
                                ERRTXT % (key, "type != %s (%s)" % (
                                    vtype, type(v))))

                self._dict[skey] = val
            else:
                raise DecodeError(ERRTXT % (key, "type != %s" % vtype))
        else:
            if val is None:
                self._dict[skey] = None
            elif isinstance(val, vtyp):  # Not necessary to do anything
                self._dict[skey] = val
            else:
                if _deser:
                    try:
                        val = _deser(val, sformat="dict")
                    except Exception as exc:
                        raise DecodeError(ERRTXT % (key, exc))

                if isinstance(val, six.string_types):
                    self._dict[skey] = val
                elif isinstance(val, list):
                    if len(val) == 1:
                        self._dict[skey] = val[0]
                    elif not len(val):
                        pass
                    else:
                        raise TooManyValues(key)
                else:
                    self._dict[skey] = val

    def to_json(self, lev=0, indent=None):
        if lev:
            return self.to_dict(lev + 1)
        else:
            return json.dumps(self.to_dict(1), indent=indent)

    def from_json(self, txt, **kwargs):
        return self.from_dict(json.loads(txt))

    def to_jwt(self, key=None, algorithm="", lev=0):
        """
        Create a signed JWT representation of the class instance

        :param key: The signing key
        :param algorithm: The signature algorithm to use
        :return: A signed JWT
        """

        _jws = JWS(self.to_json(lev), alg=algorithm)
        return _jws.sign_compact(key)

    def _add_key(self, keyjar, item, key):
        try:
            key.extend(keyjar.get_verify_key(owner=item))
        except KeyError:
            pass

    def from_jwt(self, txt, key=None, verify=True, keyjar=None, **kwargs):
        """
        Given a signed and/or encrypted JWT, verify its correctness and then
        create a class instance from the content.

        :param txt: The JWT
        :param key: keys that might be used to decrypt and/or verify the
            signature of the JWT
        :param verify: Whether the signature should be verified or not
        :param keyjar: A KeyJar that might contain the necessary key.
        :param kwargs: Extra key word arguments
        :return: A class instance
        """
        if key is None and keyjar is not None:
            key = keyjar.get_verify_key(owner="")
        elif key is None:
            key = []

        if keyjar is not None and "sender" in kwargs:
            key.extend(keyjar.get_verify_key(owner=kwargs["sender"]))

        _jw = jwe.factory(txt)
        if _jw:
            if "algs" in kwargs and "encalg" in kwargs["algs"]:
                try:
                    assert kwargs["algs"]["encalg"] == _jw["alg"]
                except AssertionError:
                    raise WrongEncryptionAlgorithm("%s != %s" % (
                        _jw["alg"], kwargs["algs"]["encalg"]))
                try:
                    assert kwargs["algs"]["encenc"] == _jw["enc"]
                except AssertionError:
                    raise WrongEncryptionAlgorithm("%s != %s" % (
                        _jw["enc"], kwargs["algs"]["encenc"]))
            if keyjar:
                dkeys = keyjar.get_decrypt_key(owner="")
            elif key:
                dkeys = key
            else:
                dkeys = []

            txt = _jw.decrypt(txt, dkeys)
            self.jwe_header = _jw.jwt.headers

        _jw = jws.factory(txt)
        if _jw:
            if "algs" in kwargs and "sign" in kwargs["algs"]:
                _alg = _jw.jwt.headers["alg"]
                try:
                    assert kwargs["algs"]["sign"] == _alg
                except AssertionError:
                    raise WrongSigningAlgorithm("%s != %s" % (
                        _alg, kwargs["algs"]["sign"]))
            try:
                _jwt = JWT().unpack(txt)
                jso = _jwt.payload()
                _header = _jwt.headers

                logger.debug("Raw JSON: {}".format(jso))
                logger.debug("header: {}".format(_header))
                if _header["alg"] == "none":
                    pass
                else:
                    if keyjar:
                        logger.debug("Issuer keys: {}".format(keyjar.keys()))
                        try:
                            _iss = jso["iss"]
                        except KeyError:
                            pass
                        else:
                            if "jku" in _header:
                                if not keyjar.find(_header["jku"], _iss):
                                    # This is really questionable
                                    try:
                                        if kwargs["trusting"]:
                                            keyjar.add(jso["iss"], _header["jku"])
                                    except KeyError:
                                        pass

                            if "kid" in _header and _header["kid"]:
                                _jw["kid"] = _header["kid"]
                                try:
                                    _key = keyjar.get_key_by_kid(_header["kid"],
                                                                 _iss)
                                    if _key:
                                        key.append(_key)
                                except KeyError:
                                    pass

                        try:
                            self._add_key(keyjar, kwargs["opponent_id"], key)
                        except KeyError:
                            pass

                    if verify:
                        if keyjar:
                            for ent in ["iss", "aud", "client_id"]:
                                if ent not in jso:
                                    continue
                                if ent == "aud":
                                    # list or basestring
                                    if isinstance(jso["aud"], six.string_types):
                                        _aud = [jso["aud"]]
                                    else:
                                        _aud = jso["aud"]
                                    for _e in _aud:
                                        self._add_key(keyjar, _e, key)
                                else:
                                    self._add_key(keyjar, jso[ent], key)

                        if "alg" in _header and _header["alg"] != "none":
                            if not key:
                                raise MissingSigningKey(
                                    "alg=%s" % _header["alg"])

                        logger.debug("Verify keys: {}".format(key))
                        _jw.verify_compact(txt, key)
            except Exception:
                raise
            else:
                self.jws_header = _jwt.headers
        else:
            jso = json.loads(txt)

        return self.from_dict(jso)

    def __str__(self):
        return '{}'.format(self.to_dict())

    def _type_check(self, typ, _allowed, val, na=False):
        if typ is six.string_types:
            if val not in _allowed:
                raise NotAllowedValue(val)
        elif typ is int:
            if val not in _allowed:
                raise NotAllowedValue(val)
        elif isinstance(typ, list):
            if isinstance(val, list):
                # _typ = typ[0]
                for item in val:
                    if item not in _allowed:
                        raise NotAllowedValue(val)
        elif val is None and na is False:
            raise NotAllowedValue(val)

    # noinspection PyUnusedLocal
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

        for (attribute, (typ, required, _, _, na)) in _spec.items():
            if attribute == "*":
                continue

            try:
                val = self._dict[attribute]
            except KeyError:
                if required:
                    raise MissingRequiredAttribute("%s" % attribute)
                continue
            else:
                if not val:
                    if required:
                        raise MissingRequiredAttribute("%s" % attribute)
                    continue

            if attribute not in _allowed:
                continue

            if isinstance(typ, tuple):
                _ityp = None
                for _typ in typ:
                    try:
                        self._type_check(_typ, _allowed[attribute], val)
                        _ityp = _typ
                        break
                    except ValueError:
                        pass
                if _ityp is None:
                    raise NotAllowedValue(val)
            else:
                self._type_check(typ, _allowed[attribute], val, na)

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

    def values(self):
        return self._dict.values()

    def __contains__(self, item):
        return item in self._dict

    def request(self, location, fragment_enc=False):
        if fragment_enc:
            return "%s#%s" % (location, self.to_urlencoded())
        else:
            if "?" in location:
                return "%s&%s" % (location, self.to_urlencoded())
            else:
                return "%s?%s" % (location, self.to_urlencoded())

    def __setitem__(self, key, value):
        try:
            (vtyp, req, _, _deser, na) = self.c_param[key]
            self._add_value(str(key), vtyp, key, value, _deser, na)
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

    # def __getattr__(self, item):
    #        return self._dict[item]

    def __delitem__(self, key):
        del self._dict[key]

    def extra(self):
        return dict([(key, val) for key, val in
                     self._dict.items() if key not in self.c_param])

    def only_extras(self):
        l = [key for key in self._dict.keys() if key in self.c_param]
        if not l:
            return True
        else:
            return False

    def update(self, item):
        if isinstance(item, dict):
            self._dict.update(item)
        elif isinstance(item, Message):
            for key, val in item.items():
                self._dict[key] = val
        else:
            raise ValueError("Can't update message using: '%s'" % (item,))

    def to_jwe(self, keys, enc, alg, lev=0):
        """

        :param keys: Dictionary, keys are key type and key is the value
        :param enc: The encryption method to use
        :param alg: Encryption algorithm
        :param lev: Used for JSON construction
        :return: A JWE
        """
        krs = keyitems2keyreps(keys)
        _jwe = JWE(self.to_json(lev), alg=alg, enc=enc)
        return _jwe.encrypt(krs)

    def from_jwe(self, msg, keys):
        krs = keyitems2keyreps(keys)
        jwe = JWE()
        _res = jwe.decrypt(msg, krs)
        return self.from_json(_res[0].decode())

    def copy(self):
        return copy.deepcopy(self)

    def weed(self):
        """
        Get rid of key value pairs that are not standard
        """
        _ext = [k for k in self._dict.keys() if k not in self.c_param]
        for k in _ext:
            del self._dict[k]

    def rm_blanks(self):
        """
        Get rid of parameters that has no value.
        """
        _blanks = [k for k in self._dict.keys() if not self._dict[k]]
        for key in _blanks:
            del self._dict[key]


# =============================================================================


def by_schema(cls, **kwa):
    return dict([(key, val) for key, val in kwa.items() if key in cls.c_param])


def add_non_standard(msg1, msg2):
    for key, val in msg2.extra().items():
        if key not in msg1.c_param:
            msg1[key] = val


# =============================================================================


# noinspection PyUnusedLocal
def list_serializer(vals, sformat="urlencoded", lev=0):
    if isinstance(vals, six.string_types) or not isinstance(vals, list):
        raise ValueError("Expected list: %s" % vals)
    if sformat == "urlencoded":
        return " ".join(vals)
    else:
        return vals


# noinspection PyUnusedLocal
def list_deserializer(val, sformat="urlencoded"):
    if sformat == "urlencoded":
        if isinstance(val, six.string_types):
            return val.split(" ")
        elif isinstance(val, list) and len(val) == 1:
            return val[0].split(" ")
    else:
        return val


# noinspection PyUnusedLocal
def sp_sep_list_serializer(vals, sformat="urlencoded", lev=0):
    if isinstance(vals, six.string_types):
        return vals
    else:
        return " ".join(vals)


# noinspection PyUnusedLocal
def sp_sep_list_deserializer(val, sformat="urlencoded"):
    if isinstance(val, six.string_types):
        return val.split(" ")
    elif isinstance(val, list) and len(val) == 1:
        return val[0].split(" ")
    else:
        return val


# noinspection PyUnusedLocal
def json_serializer(obj, sformat="urlencoded", lev=0):
    return json.dumps(obj)


# noinspection PyUnusedLocal
def json_deserializer(txt, sformat="urlencoded"):
    return json.loads(txt)


VTYPE = 0
VREQUIRED = 1
VSER = 2
VDESER = 3
VNULLALLOWED = 4

SINGLE_REQUIRED_STRING = (basestring, True, None, None, False)
SINGLE_OPTIONAL_STRING = (basestring, False, None, None, False)
SINGLE_OPTIONAL_INT = (int, False, None, None, False)
OPTIONAL_LIST_OF_STRINGS = ([basestring], False, list_serializer,
                            list_deserializer, False)
REQUIRED_LIST_OF_STRINGS = ([basestring], True, list_serializer,
                            list_deserializer, False)
OPTIONAL_LIST_OF_SP_SEP_STRINGS = ([basestring], False, sp_sep_list_serializer,
                                   sp_sep_list_deserializer, False)
REQUIRED_LIST_OF_SP_SEP_STRINGS = ([basestring], True, sp_sep_list_serializer,
                                   sp_sep_list_deserializer, False)
SINGLE_OPTIONAL_JSON = (basestring, False, json_serializer, json_deserializer,
                        False)

REQUIRED = [SINGLE_REQUIRED_STRING, REQUIRED_LIST_OF_STRINGS,
            REQUIRED_LIST_OF_SP_SEP_STRINGS]

#
# =============================================================================
#


class ErrorResponse(Message):
    c_param = {"error": SINGLE_REQUIRED_STRING,
               "error_description": SINGLE_OPTIONAL_STRING,
               "error_uri": SINGLE_OPTIONAL_STRING}


class AuthorizationErrorResponse(ErrorResponse):
    c_param = ErrorResponse.c_param.copy()
    c_param.update({"state": SINGLE_OPTIONAL_STRING})
    c_allowed_values = ErrorResponse.c_allowed_values.copy()
    c_allowed_values.update({"error": ["invalid_request",
                                       "unauthorized_client",
                                       "access_denied",
                                       "unsupported_response_type",
                                       "invalid_scope", "server_error",
                                       "temporarily_unavailable"]})


class TokenErrorResponse(ErrorResponse):
    c_allowed_values = {"error": ["invalid_request", "invalid_client",
                                  "invalid_grant", "unauthorized_client",
                                  "unsupported_grant_type",
                                  "invalid_scope"]}


class AccessTokenRequest(Message):
    c_param = {"grant_type": SINGLE_REQUIRED_STRING,
               "code": SINGLE_REQUIRED_STRING,
               "redirect_uri": SINGLE_REQUIRED_STRING,
               "client_id": SINGLE_OPTIONAL_STRING,
               "client_secret": SINGLE_OPTIONAL_STRING}
    c_default = {"grant_type": "authorization_code"}


class AuthorizationRequest(Message):
    c_param = {
        "response_type": REQUIRED_LIST_OF_SP_SEP_STRINGS,
        "client_id": SINGLE_REQUIRED_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "redirect_uri": SINGLE_OPTIONAL_STRING,
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
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS
    }


class CCAccessTokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS
    }
    c_default = {"grant_type": "client_credentials"}
    c_allowed_values = {"grant_type": ["client_credentials"]}


class RefreshAccessTokenRequest(Message):
    c_param = {
        "grant_type": SINGLE_REQUIRED_STRING,
        "refresh_token": SINGLE_REQUIRED_STRING,
        "client_id": SINGLE_REQUIRED_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "client_secret": SINGLE_OPTIONAL_STRING
    }
    c_default = {"grant_type": "refresh_token"}
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
        raise FormatError("Unknown message type: %s" % msgtype)
