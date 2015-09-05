import copy
import uuid
import time
import itertools
import hmac
import hashlib
import random
import base64
import logging

import six

from Crypto.Cipher import AES

from oic.oic import AuthorizationRequest
from oic.oauth2 import rndstr
from oic.utils.time_util import utc_time_sans_frac

__author__ = 'rohe0002'

logger = logging.getLogger(__name__)


class ExpiredToken(Exception):
    pass


class WrongTokenType(Exception):
    pass


class AccessCodeUsed(Exception):
    pass


def pairwise_id(sub, sector_identifier, seed):
    return hashlib.sha256(("%s%s%s" % (sub, sector_identifier, seed)).encode("utf-8")).hexdigest()


class Crypt():
    def __init__(self, password, mode=AES.MODE_CBC):
        self.password = password or 'kitty'
        self.key = hashlib.sha256(password.encode("utf-8")).digest()
        self.mode = mode

    def encrypt(self, text):
        # setting iv because the underlying AES module misbehaves
        # on certain platforms
        encryptor = AES.new(self.key, self.mode, IV="0" * 16)

        if len(text) % 16:
            text += ' ' * (16 - len(text) % 16)

        return encryptor.encrypt(text)

    def decrypt(self, ciphertext):
        decryptor = AES.new(self.key, self.mode, IV="0" * 16)
        return decryptor.decrypt(ciphertext)


class Token(object):
    def __init__(self, secret, password):
        self.secret = secret
        self._rndlen = 19
        self._sidlen = 56
        self.crypt = Crypt(password)

    def __call__(self, ttype="A", prev="", sid=None):
        if prev:
            ptyp, sid, tmp = self._split_token(prev)
            if not ttype:
                ttype = ptyp
        else:
            tmp = ""

        rnd = tmp
        while rnd == tmp:
            rnd = rndstr(self._rndlen)
            # Ultimate length multiple of 16

        return base64.b64encode(self.crypt.encrypt("%s%s%s" % (sid, ttype,
                                                               rnd))).decode("utf-8")

    def key(self, user="", areq=None):
        csum = hmac.new(self.secret.encode("utf-8"), digestmod=hashlib.sha224)
        csum.update(("%s" % utc_time_sans_frac()).encode("utf-8"))
        csum.update(("%f" % random.random()).encode("utf-8"))
        if user:
            csum.update(user.encode("utf-8"))

        if areq:
            try:
                csum.update(areq["state"].encode("utf-8"))
            except KeyError:
                pass

            try:
                for val in areq["scope"]:
                    csum.update(val.encode("utf-8"))
            except KeyError:
                pass

            try:
                csum.update(areq["redirect_uri"].encode("utf-8"))
            except KeyError:
                pass

        return csum.hexdigest()  # 56 bytes long, 224 bits

    def _split_token(self, token):
        plain = self.crypt.decrypt(base64.b64decode(token))
        # first _sidlen bytes are the sid
        _sid = plain[:self._sidlen]
        _type = plain[self._sidlen]
        try:
            # Python 2 <-> 3
            _type = chr(_type)
            _sid = _sid.decode()
        except TypeError:
            pass

        _rnd = plain[self._sidlen + 1:]
        return _type, _sid, _rnd

    def type_and_key(self, token):
        a, b, c = self._split_token(token)
        return a, b

    def get_key(self, token):
        return self._split_token(token)[1]

    def get_type(self, token):
        return self._split_token(token)[0]


class AuthnEvent(object):
    def __init__(self, uid, salt, valid=3600, authn_info=None, time_stamp=0):
        """
        Creates a representation of an authentication event.

        :param uid: The local user identifier
        :param salt: Salt to be used in creating a sub
        :param valid: How long the authentication is expected to be valid
        :param authn_info: Info about the authentication event
        :return:
        """
        self.uid = uid
        self.salt = salt
        self.authn_time = int(time_stamp) or time.time()
        self.valid_until = self.authn_time + int(valid)
        self.authn_info = authn_info

    def valid(self):
        return self.valid_until > time.time()

    def valid_for(self):
        return self.valid_until - time.time()


class SessionDB(object):
    def __init__(self, base_url, db=None, secret="Ab01FG65",
                 token_expires_in=3600, password="4-amino-1H-pyrimidine-2-one",
                 grant_expires_in=600, seed=""):
        self.base_url = base_url
        if db:
            self._db = db
        else:
            self._db = {}
        self.token = Token(secret, password)
        self.token_expires_in = token_expires_in
        self.grant_expires_in = grant_expires_in
        self.uid2sid = {}
        self.seed = seed or secret

    def __getitem__(self, item):
        """
        :param item: authz grant code or refresh token
        """
        try:
            return self._db[item]
        except KeyError:
            try:
                sid = self.token.get_key(item)
            except Exception:
                raise KeyError("item '%s' could not be found" % str(item))
            return self._db[sid]

    def __setitem__(self, key, value):
        """
        :param key: authz grant code or refresh token
        """

        self._db[key] = value

    def __delitem__(self, sid):
        """
        Actually delete the pointed session from this SessionDB instance
        :param key: session identifier
        """
        del self._db[sid]
        # Delete the mapping for session id
        self.uid2sid = {k: v for k, v in self.uid2sid.items() if sid not in v}

    def update(self, key, attribute, value):
        if key in self._db:
            pass
        else:
            try:
                sid = self.token.get_key(key)
            except Exception:
                raise KeyError

            if sid not in self._db:
                raise KeyError
            else:
                key = sid

        item = self._db[key]
        item[attribute] = value
        self._db[key] = item

    def update_by_token(self, token, attribute, value):
        (typ, key) = self.token.type_and_key(token)
        return self.update(key, attribute, value)

    def do_sub(self, sid, client_salt, sector_id="", subject_type="public"):
        """
        Construct a sub (subject identifier)

        :param sid: Session identifier
        :param sector_id: Possible sector identifier
        :param subject_type: 'public'/'pairwise'
        :param client_salt: client specific salt - used in pairwise
        :return:
        """
        uid = self._db[sid]["authn_event"].uid
        user_salt = self._db[sid]["authn_event"].salt

        if subject_type == "public":
            sub = hashlib.sha256("{}{}".format(uid, user_salt).encode("utf-8")).hexdigest()
        else:
            sub = pairwise_id(uid, sector_id, "{}{}".format(client_salt, user_salt))

        # since sub can be public, there can be more then one session
        # that uses the same subject identifier
        try:
            self.uid2sid[uid].append(sid)
        except KeyError:
            self.uid2sid[uid] = [sid]

        logger.debug("uid2sid: %s" % self.uid2sid)
        self.update(sid, 'sub', sub)

        return sub

    def create_authz_session(self, aevent, areq, id_token=None, oidreq=None,
                             **kwargs):
        """

        :param aevent: An AuthnEvent instance
        :param areq: The AuthorizationRequest instance
        :param id_token: An IDToken instance
        :param oidreq: An OpenIDRequest instance
        :return: The session identifier, which is the database key
        """

        sid = self.token.key(user=aevent.uid, areq=areq)
        access_grant = self.token(sid=sid)

        _dic = {
            "oauth_state": "authz",
            "code": access_grant,
            "code_used": False,
            "authzreq": areq.to_json(),
            "client_id": areq["client_id"],
            "revoked": False,
            "authn_event": aevent
        }

        _dic.update(kwargs)

        try:
            _val = areq["nonce"]
            if _val:
                _dic["nonce"] = _val
        except (AttributeError, KeyError):
            pass

        for key in ["redirect_uri", "state", "scope", "si_redirects"]:
            try:
                _dic[key] = areq[key]
            except KeyError:
                pass

        if id_token:
            _dic["id_token"] = id_token
        if oidreq:
            _dic["oidreq"] = oidreq.to_json()

        self._db[sid] = _dic

        return sid

    def get_authentication_event(self, sid):
        return self._db[sid]["authn_event"]

    def get_token(self, sid):
        if self._db[sid]["oauth_state"] == "authz":
            return self._db[sid]["code"]
        elif self._db[sid]["oauth_state"] == "token":
            return self._db[sid]["access_token"]

    def upgrade_to_token(self, token=None, issue_refresh=True, id_token="",
                         oidreq=None, key=None, access_grant=""):
        """

        :param token: The access grant
        :param issue_refresh: If a refresh token should be issued
        :param id_token: An IDToken instance
        :param oidreq: An OpenIDRequest instance
        :param key: The session key. One of token or key must be given.
        :return: The session information as a dictionary
        """
        if token:
            try:
                (typ, key) = self.token.type_and_key(token)
            except (ValueError, TypeError):
                (typ, key) = self.token.type_and_key(access_grant)
                token = access_grant

            if typ != "A":  # not a access grant
                raise WrongTokenType("Not a grant token")

            dic = self._db[key]

            if dic["code_used"]:
                raise AccessCodeUsed()
            _at = self.token("T", token)
            dic["code_used"] = True
        else:
            dic = self._db[key]
            _at = self.token("T", sid=key)

        dic["access_token"] = _at
        dic["access_token_scope"] = "?"
        dic["oauth_state"] = "token"
        dic["token_type"] = "Bearer"
        dic["expires_in"] = self.token_expires_in
        dic["token_expires_at"] = utc_time_sans_frac() + self.token_expires_in
        if id_token:
            dic["id_token"] = id_token
        if oidreq:
            dic["oidreq"] = oidreq

        if issue_refresh:
            dic["refresh_token"] = self.token("R", token)

        self._db[key] = dic
        return dic

    def refresh_token(self, rtoken):
        # assert that it is a refresh token
        typ = self.token.get_type(rtoken)
        if typ == "R":
            if not self.is_valid(rtoken):
                raise ExpiredToken()

            sid = self.token.get_key(rtoken)

            # This might raise an error
            dic = self._db[sid]

            access_token = self.token("T", prev=rtoken)

            dic["token_expires_at"] = utc_time_sans_frac() + self.token_expires_in
            # dic["client_id_issued_at"] = utc_time_sans_frac()
            dic["access_token"] = access_token
            self._db[sid] = dic
            # self._db[dic["xxxx"]] = dic
            return dic
        else:
            raise WrongTokenType("Not a refresh token!")

    @staticmethod
    def is_expired(sess):
        if "token_expires_at" in sess:
            if sess["token_expires_at"] < utc_time_sans_frac():
                return True

        return False

    def is_valid(self, token):
        typ, sid = self.token.type_and_key(token)

        _dic = self._db[sid]
        if typ == "A":
            if _dic["code"] != token:
                return False
            elif _dic["oauth_state"] != "authz":
                return False

            if self.is_expired(_dic):
                return False

        elif typ == "T":
            if _dic["access_token"] != token:
                return False

            if self.is_expired(_dic):
                return False

        elif typ == "R" and _dic["refresh_token"] != token:
            return False

        return True

    def is_revoked(self, sid):
        # typ, sid = self.token.type_and_key(token)
        try:
            return self[sid]["revoked"]
        except KeyError:
            return False

    def revoke_token(self, token):
        # revokes either the refresh token or the access token

        typ, sid = self.token.type_and_key(token)

        _dict = self._db[sid]
        if typ == "A":
            _dict["code"] = ""
        elif typ == "T":
            _dict["access_token"] = ""
        elif typ == "R":
            _dict["refresh_token"] = ""
        else:
            pass
        self._db[sid] = _dict
        return True

    def revoke_all_tokens(self, token):
        typ, sid = self.token.type_and_key(token)

        self.update(sid, 'revoked', True)

    def get_client_id_for_session(self, sid):
        _dict = self._db[sid]
        return _dict["client_id"]

    def get_client_ids_for_uid(self, uid):
        return [self.get_client_id_for_session(sid) for sid in self.uid2sid[uid]]

    def get_verified_Logout(self, uid):
        _dict = self._db[self.uid2sid[uid]]
        if "verified_logout" not in _dict:
            return None
        return _dict["verified_logout"]

    def set_verify_logout(self, uid):
        _dict = self._db[self.uid2sid[uid]]
        _dict["verified_logout"] = uuid.uuid4().urn

    def get_token_id(self, uid):
        _dict = self._db[self.uid2sid[uid]]
        return _dict["id_token"]

    def is_revoke_uid(self, uid):
        return self._db[self.uid2sid[uid]]["revoked"]

    def revoke_uid(self, uid):
        self.update(self.uid2sid[uid], 'revoked', True)

    def get_sids_from_uid(self, uid):
        """
        Returns list of identifiers for sessions that are connected to this
        local identifier

        :param uid: local identifier (username)
        :return: list of session identifiers
        """
        return self.uid2sid[uid]

    def get_sids_by_sub(self, sub):
        sids = itertools.chain.from_iterable(self.uid2sid.values())
        return [sid for sid in sids if self._db[sid]["sub"] == sub]

    def duplicate(self, sinfo):
        _dic = copy.copy(sinfo)
        areq = AuthorizationRequest().from_json(_dic["authzreq"])
        sid = self.token.key(user=_dic["sub"], areq=areq)

        _dic["code"] = self.token(sid=sid)
        _dic["code_used"] = False

        for key in ["access_token", "access_token_scope", "oauth_state",
                    "token_type", "token_expires_at", "expires_in",
                    "client_id_issued_at", "id_token", "oidreq",
                    "refresh_token"]:
            try:
                del _dic[key]
            except KeyError:
                pass

        self._db[sid] = _dic
        self.uid2sid[_dic["sub"]] = sid
        return sid

    def read(self, token):
        (typ, key) = self.token.type_and_key(token)

        if typ != "T":  # not a access grant
            raise WrongTokenType("Not a grant token")

        return self._db[key]
