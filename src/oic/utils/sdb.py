import copy
import uuid
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
        self._sidlen = 28
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

        return csum.digest()  # 28 bytes long, 224 bits

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


class SessionDB(object):
    def __init__(self, db=None, secret="Ab01FG65", token_expires_in=3600,
                 password="4-amino-1H-pyrimidine-2-one",
                 grant_expires_in=600, seed=""):
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
                raise KeyError
            return self._db[sid]

    def __setitem__(self, key, value):
        """
        :param key: authz grant code or refresh token
        """

        self._db[key] = value

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

    def do_userid(self, sid, sub, sector_id, preferred_id_type):
        old = [""]
        if preferred_id_type == "public":
            uid = sub
        else:
            uid = pairwise_id(sub, sector_id, self.seed)
            old.append(sub)

        logger.debug("uid: %s, old: %s" % (uid, old))
        self.uid2sid[uid] = sid

        for old_id in old:
            try:
                del self.uid2sid[old_id]
            except KeyError:
                pass

        logger.debug("uid2sid: %s" % self.uid2sid)
        self._db[sid]["local_sub"] = sub
        self._db[sid]["sub"] = uid

        return uid

    def create_authz_session(self, sub, areq, id_token=None, oidreq=None):
        """

        :param sub: Identifier for the user, this is the real identifier
        :param areq: The AuthorizationRequest instance
        :param id_token: An IDToken instance
        :param oidreq: An OpenIDRequest instance
        :return: The session identifier, which is the database key
        """

        sid = self.token.key(user=sub, areq=areq)
        access_grant = self.token(sid=sid)

        _dic = {
            "oauth_state": "authz",
            "local_sub": sub,
            "sub": sub,
            "code": access_grant,
            "code_used": False,
            "authzreq": areq.to_json(),
            "client_id": areq["client_id"],
            "revoked": False,
        }

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
        self.uid2sid[sub] = sid
        return sid

    def update_to_token(self, token=None, issue_refresh=True, id_token="",
                        oidreq=None, key=None):
        """

        :param token: The access grant
        :param issue_refresh: If a refresh token should be issued
        :param id_token: An IDToken instance
        :param oidreq: An OpenIDRequest instance
        :param key: The session key. One of token or key must be given.
        :return: The session information as a dictionary
        """
        if token:
            (typ, key) = self.token.type_and_key(token)

            if typ != "A":  # not a access grant
                raise WrongTokenType("Not a grant token")

            dic = self._db[key]

            if dic["code_used"]:
                raise Exception("Access code already used!!")
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
            #dic["client_id_issued_at"] = utc_time_sans_frac()
            dic["access_token"] = access_token
            self._db[sid] = dic
            #self._db[dic["xxxx"]] = dic
            return dic
        else:
            raise WrongTokenType("Not a refresh token!")

    def is_expired(self, sess):
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
        #typ, sid = self.token.type_and_key(token)
        try:
            return self[sid]["revoked"]
        except KeyError:
            return False

#    def set_oir(self, key, oir):
#        self._db[key] = oir.dictionary()
#
#    def get_oir(self, key):
#        return OpenIDRequest(**self._db[key])

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

    def getClient_id(self, uid):
        _dict = self._db[self.uid2sid[uid]]
        return _dict["client_id"]

    def getVerifyLogout(self, uid):
        _dict = self._db[self.uid2sid[uid]]
        if "verify_logout" not in _dict:
            return None
        return _dict["verify_logout"]

    def setVerifyLogout(self, uid):
        _dict = self._db[self.uid2sid[uid]]
        _dict["verify_logout"] = uuid.uuid4().urn

    def getToken_id(self, uid):
        _dict = self._db[self.uid2sid[uid]]
        return _dict["id_token"]

    def is_revoke_uid(self, uid):
        return self._db[self.uid2sid[uid]]["revoked"]

    def revoke_uid(self, uid):
        self._db[self.uid2sid[uid]]["revoked"] = True

    def get_sid_from_userid(self, uid):
        return self.uid2sid[uid]

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
