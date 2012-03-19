__author__ = 'rohe0002'

import hmac
import hashlib
import time
import random
import base64

from oic.oauth2 import rndstr
from oic.utils.time_util import utc_time_sans_frac

from Crypto.Cipher import AES

class ExpiredToken(Exception):
    pass

class WrongTokenType(Exception):
    pass


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

class Token(object):
    def __init__(self, secret, password):
        self.secret = secret
        self._rndlen = 19
        self._sidlen = 28
        self.crypt = Crypt(password)

    def __call__(self, type="A", prev="", sid=None):
        if prev:
            ptyp, sid, tmp = self._split_token(prev)
            if not type:
                type = ptyp
        else:
            tmp = ""

        rnd = tmp
        while rnd == tmp:
            rnd = rndstr(self._rndlen)
            # Ultimate length multiple of 16

        return base64.b64encode(self.crypt.encrypt("%s%s%s" % (sid, type, rnd)))

    def key(self, user="", areq=None):
        csum = hmac.new(self.secret, digestmod=hashlib.sha224)
        csum.update("%s" % time.time())
        csum.update("%f" % random.random())
        if user:
            csum.update(user)

        if areq:
            csum.update(areq["state"])
            try:
                for val in areq["scope"]:
                    csum.update(val)
            except KeyError:
                pass

            try:
                csum.update(areq["redirect_uri"])
            except KeyError:
                pass

        return csum.digest() # 28 bytes long, 224 bits

    def _split_token(self, token):
        plain = self.crypt.decrypt(base64.b64decode(token))
        # first _sidlen bytes are the sid
        _sid = plain[:self._sidlen]
        _type = plain[self._sidlen]
        _rnd = plain[self._sidlen+1:]
        return _type, _sid, _rnd

    def type_and_key(self, token):
        a, b, c = self._split_token(token)
        return a, b

    def get_key(self, token):
        return self._split_token(token)[1]

    def get_type(self, token):
        return self._split_token(token)[0]

class SessionDB(object):
    def __init__(self, db=None, secret = "Ab01FG65", token_expires_in=3600,
                 password="4-amino-1H-pyrimidine-2-one",
                 grant_expires_in=600):
        if db:
            self._db = db
        else:
            self._db = {}
        self.token = Token(secret, password)
        self.token_expires_in = token_expires_in
        self.grant_expires_in = grant_expires_in

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


    def create_authz_session(self, user_id, areq, id_token=None, oidreq=None):
        """

        :param user_id: Identifier for the user, this is the real identifier
        :param areq: The AuthorizationRequest instance
        :param id_token: An IDToken instance
        :param oidreq: An OpenIDRequest instance
        :return: The session identifier, which is the database key
        """

        sid = self.token.key(user=user_id, areq=areq)
        access_grant = self.token(sid=sid)

        _dic  = {
            "oauth_state": "authz",
            "user_id": user_id,
            "code": access_grant,
            "code_used": False,
            "authzreq": areq.to_json(),
            "client_id": areq["client_id"],
            "expires_in": self.grant_expires_in,
            "expires_at": utc_time_sans_frac()+self.grant_expires_in,
            "issued": time.time()
        }

        try:
            _val = areq["nonce"]
            if _val:
                _dic["nonce"] = _val
        except (AttributeError, KeyError):
            pass

        for key in ["redirect_uri", "state", "scope"]:
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

            if typ != "A": # not a access grant
                raise WrongTokenType("Not a grant token")

            dic = self._db[key]

            if dic["code_used"]:
                raise Exception("Already used!!")
            _at = self.token("T", token)
            dic["code_used"] = True
        else:
            dic = self._db[key]
            _at = self.token("T", sid=key)


        dic["access_token"] = _at
        dic["access_token_scope"] = "?"
        dic["oauth_state"] = "token"
        dic["token_type"] = "Bearer"
        dic["expires_at"] = utc_time_sans_frac()+self.token_expires_in
        dic["expires_in"] = self.token_expires_in
        dic["issued"] = time.time()
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

            dic["issued"] = time.time()
            dic["access_token"] = access_token
            self._db[sid] = dic
            #self._db[dic["xxxx"]] = dic
            return dic
        else:
            raise WrongTokenType("Not a refresh token!")

    def is_expired(self, sess):
        if "issued" in sess:
            if (sess["issued"] + sess["expires_in"]) < time.time():
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


