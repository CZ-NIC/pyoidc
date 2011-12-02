__author__ = 'rohe0002'

import hmac
import hashlib
import time
import random
import base64
import string

from oic.oic import OpenIDRequest
from oic import oauth2


def xxxx(secret, user, areq, redirect_uri=""):
    """Generates a session key."""
    csum = hmac.new(secret, digestmod=hashlib.sha256)
    if user:
        csum.update(user)
    csum.update(areq.state)
    if areq.state:
        for val in areq.scope:
            csum.update(val)
    if areq.redirect_uri:
        csum.update(areq.redirect_uri)
    else:
        csum.update(redirect_uri)
    return csum.hexdigest()

#noinspection PyUnusedLocal

class SessionDB(object):
    def __init__(self, db=None, secret = "Ab01FG65", token_expires_in=3600,
                 password="4-amino-1H-pyrimidine-2-one"):
        if db:
            self._db = db
        else:
            self._db = {}
        self.secret = secret
        self.token_expires_in = token_expires_in
        self.crypt = oauth2.Crypt(password)

    def __getitem__(self, item):
        """
        :param item: authz grant code or refresh token
        """
        try:
            return self._db[item]
        except KeyError:
            _, sid, _ = self.get_type_and_key(item)
            return self._db[sid]

    def __setitem__(self, key, value):
        """
        :param key: authz grant code or refresh token
        """

        self._db[key] = value

    def update(self, key, attribute, value):
        try:
            item = self._db[key]
        except KeyError:
            _, sid, _ = self.get_type_and_key(key)
            item = self._db[sid]
            key = sid

        self._db[key][attribute] = value

    def session(self, type="A", prev="", user="", areq=None):
        """

        :return: session id (sid) and encrypted tuple
        """
        if prev:
            ptyp, sid, num = self.get_type_and_key(prev)
            if not type:
                type = ptyp
        else:
            sid = num = ""

        if not sid:
            csum = hmac.new(self.secret, digestmod=hashlib.sha224)
            csum.update("%s" % time.time())
            csum.update("%f" % random.random())
            if user:
                csum.update(user)
            if areq:
                csum.update(areq.state)
                if areq.state:
                    for val in areq.scope:
                        csum.update(val)
                if areq.redirect_uri:
                    csum.update(areq.redirect_uri)
            sid = csum.digest() # 28 bytes long, 224 bits
            #hsid = csum.hexdigest() # 56 bytes
        rnd = num
        while rnd == num:
            rnd = ''.join([random.choice(string.letters) for x in xrange(3)])
        ctext = self.crypt.encrypt("%s%s%s" % (sid, type, rnd))
        return sid, base64.b64encode(ctext)

    def get_type_and_key(self, token):
        plain = self.crypt.decrypt(base64.b64decode(token))
        return plain[-4], plain[:-4], plain[-3:]

    def create_authz_session(self, user_id, areq, id_token=None, oidreq=None):
        """

        :param user_id: Identifier for the user, this is the real identifier
        :param areq: The AuthorizationRequest instance
        :param id_token: An IDToken instance
        :param oidreq: An OpenIDRequest instance
        :return: The session identifier, which is the database key
        """

        sid, access_grant = self.session(user=user_id, areq=areq)
        _dic  = {
            "oauth_state": "authz",
            "user_id": user_id,
            "code": access_grant,
            "authzreq": areq.get_json(),
            "client_id": areq.client_id,
        }

        try:
            _dic["nonce"] = areq.nonce
        except (AttributeError, KeyError):
            pass
        
        if areq.redirect_uri:
            _dic["redirect_uri"] = areq.redirect_uri
        if areq.state:
            _dic["state"] = areq.state

        # Just an assumption
        if areq.scope:
            _dic["scope"] = areq.scope

        if id_token:
            _dic["id_token"] = id_token
        if oidreq:
            _dic["oidreq"] = oidreq.get_json()

        self._db[sid] = _dic
        return sid

    def update_to_token(self, token, issue_refresh=True, id_token="",
                        oidreq=None):
        """

        :param token: The access grant
        :param issue_refresh: If a refresh token should be issued
        :param id_token: An IDToken instance
        :param oidreq: An OpenIDRequest instance
        :return: The session information as a dictionary
        """
        (typ, key, _) = self.get_type_and_key(token)

        if typ != "A": # not a access grant
            raise Exception("Wrong type of token")
        
        dic = self._db[key]

        if dic["oauth_state"] == "token":
            return Exception("Already used!!")

        _, _at = self.session("T", token)
        dic["access_token"] = _at
        dic["access_token_scope"] = "?"
        dic["oauth_state"] = "token"
        dic["token_type"] = "bearer"
        dic["expires_in"] = self.token_expires_in
        dic["issued"] = time.time()
        if id_token:
            dic["id_token"] = id_token
        if oidreq:
            dic["oidreq"] = oidreq

        if issue_refresh:
            _, dic["refresh_token"] = self.session("R", token)

        self._db[key] = dic
        return dic

    def refresh_token(self, rtoken):
        # assert that it is a refresh token
        (typ, _, _) = self.get_type_and_key(rtoken)
        if typ == "R":
            sid, access_token = self.session(prev=rtoken)

            # This might raise an error
            dic = self._db[sid]

            dic["issued"] = time.time()
            dic["oauth_token"] = access_token
            self._db[sid] = dic
            #self._db[dic["xxxx"]] = dic
            return dic
        else:
            raise Exception("Not a refresh token!")

    def valid(self, token):
        (typ, sid, _) = self.get_type_and_key(token)

        _dic = self._db[sid]
        if typ == "A" and not _dic["access_grant"]:
            return False
        elif typ == "T" and not _dic["oauth_token"]:
            return False
        elif typ == "R" and not _dic["oauth_refresh_token"]:
            return False
        elif _dic["issued"] + _dic["oauth_token_expires_in"] < time.time():
            return False
        else:
            return True

    def set_oir(self, key, oir):
        self._db[key] = oir.dictionary()

    def get_oir(self, key):
        return OpenIDRequest(**self._db[key])

    def revoke_token(self, token):
        # revokes either the refresh token or the access token

        (typ, sid, _) = self.get_type_and_key(token)

        _dict = self._db[sid]
        if typ == "A":
            _dict["oauth_token"] = ""
        elif typ == "R":
            _dict["oauth_refresh_token"] = ""
        else:
            pass

        return True


