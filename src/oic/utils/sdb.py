import copy
import uuid

import time
from oic.oic import AuthorizationRequest


__author__ = 'rohe0002'

import hmac
import hashlib
import random
import base64
import logging

from oic.oauth2 import rndstr
from oic.utils.time_util import utc_time_sans_frac

from Crypto.Cipher import AES

logger = logging.getLogger(__name__)


class ExpiredToken(Exception):
    pass


class WrongTokenType(Exception):
    pass


class AccessCodeUsed(Exception):
    pass


def pairwise_id(sub, sector_identifier, seed):
    return hashlib.sha256("%s%s%s" % (sub, sector_identifier, seed)).hexdigest()


class Crypt():
    def __init__(self, password, mode=AES.MODE_CBC):
        self.password = password or 'kitty'
        self.key = hashlib.sha256(password).digest()
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
                                                               rnd)))

    def key(self, user="", areq=None):
        csum = hmac.new(self.secret, digestmod=hashlib.sha224)
        csum.update("%s" % utc_time_sans_frac())
        csum.update("%f" % random.random())
        if user:
            csum.update(user)

        if areq:
            try:
                csum.update(areq["state"])
            except KeyError:
                pass

            try:
                for val in areq["scope"]:
                    csum.update(val)
            except KeyError:
                pass

            try:
                csum.update(areq["redirect_uri"])
            except KeyError:
                pass

        return csum.hexdigest()  # 56 bytes long, 224 bits

    def _split_token(self, token):
        plain = self.crypt.decrypt(base64.b64decode(token))
        # first _sidlen bytes are the sid
        _sid = plain[:self._sidlen]
        _type = plain[self._sidlen]
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
    def __init__(self, uid, valid=3600, authn_info=None):
        """
        Creates a representation of an authentication event.

        :param uid: The local user identifier
        :param valid: How long the authentication is expected to be valid
        :param authn_info: Info about the authentication event
        :return:
        """
        self.uid = uid
        self.authn_time = int(time.time())
        self.valid_until = self.authn_time + int(valid)
        self.authn_info = authn_info

    def valid(self):
        return self.valid_until > int(time.time())

    def valid_for(self):
        return self.valid_until - int(time.time())


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
        self.sub2sid = {}
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

    def __delitem__(self, key):
        """
        Actually delete the pointed session from this SessionDB instance
        :param key: session identifier
        """
        del self._db[key]

    def keys(self):
        return self._db.keys()

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

        self._db[key][attribute] = value

    def update_by_token(self, token, attribute, value):
        (typ, key) = self.token.type_and_key(token)
        return self.update(key, attribute, value)

    def do_sub(self, sid, sector_id="", preferred_id_type="public"):
        """
        Construct a sub (subject identifier)

        :param sid: Session identifier
        :param sector_id: Possible sector identifier
        :param preferred_id_type: 'public'/'pairwise'
        :return:
        """
        uid = self._db[sid]["authn_event"].uid
        
        old = [""]
        if preferred_id_type == "public":
            sub = "%x" % hash(uid+self.base_url)
        else:
            sub = pairwise_id(uid, sector_id, self.seed)
            old.append(sub)

        logger.debug("sub: %s, old: %s" % (sub, old))

        # since sub can be public, there can be more then one session
        # that uses the same subject identifier
        try:
            self.sub2sid[sub].append(sid)
        except KeyError:
            self.sub2sid[sub] = [sid]

        for old_id in old:
            try:
                del self.sub2sid[old_id]
            except KeyError:
                pass

        logger.debug("sub2sid: %s" % self.sub2sid)
        self._db[sid]["sub"] = sub

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

    def get_token(self, key):
        if self._db[key]["oauth_state"] == "authz":
            return self._db[key]["code"]
        elif self._db[key]["oauth_state"] == "token":
            return self._db[key]["access_token"]

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

        return True

    def revoke_all_tokens(self, token):
        typ, sid = self.token.type_and_key(token)

        self._db[sid]["revoked"] = True

    def get_client_id(self, sub):
        _dict = self._db[self.sub2sid[sub]]
        return _dict["client_id"]

    def get_verified_Logout(self, sub):
        _dict = self._db[self.sub2sid[sub]]
        if "verified_logout" not in _dict:
            return None
        return _dict["verified_logout"]

    def set_verify_logout(self, sub):
        _dict = self._db[self.sub2sid[sub]]
        _dict["verified_logout"] = uuid.uuid4().urn

    def get_token_id(self, sub):
        _dict = self._db[self.sub2sid[sub]]
        return _dict["id_token"]

    def is_revoke_uid(self, sub):
        return self._db[self.sub2sid[sub]]["revoked"]

    def revoke_uid(self, sub):
        self._db[self.sub2sid[sub]]["revoked"] = True

    def get_sids_from_sub(self, sub):
        """
        Returns list of identifiers for sessions that are connected to this
        subject identifier

        :param sub: subject identifier
        :return: list of session identifiers
        """
        return self.sub2sid[sub]

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
        self.sub2sid[_dic["sub"]] = sid
        return sid

    def read(self, token):
        (typ, key) = self.token.type_and_key(token)

        if typ != "T":  # not a access grant
            raise WrongTokenType("Not a grant token")

        return self._db[key]
