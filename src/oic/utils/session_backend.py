import json
import time
from abc import ABCMeta
from abc import abstractmethod
from typing import Dict
from typing import List
from typing import Optional

from oic.utils.time_util import time_sans_frac


class AuthnEvent(object):
    def __init__(
            self,
            uid,
            salt,
            valid=3600,
            authn_info=None,
            time_stamp=0,
            authn_time=None,
            valid_until=None,
    ):
        """
        Create a representation of an authentication event.

        :param uid: The local user identifier
        :param salt: Salt to be used in creating a sub
        :param valid: How long the authentication is expected to be valid
        :param authn_info: Info about the authentication event
        :return:
        """
        self.uid = uid
        self.salt = salt
        self.authn_time = authn_time or (int(time_stamp) or time_sans_frac())
        self.valid_until = valid_until or (self.authn_time + int(valid))
        self.authn_info = authn_info

    def valid(self):
        return self.valid_until > time.time()

    def valid_for(self):
        return self.valid_until - time.time()

    def to_json(self):
        """Serialize AuthnEvent to JSON."""
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, json_struct):
        """Create AuthnEvent from JSON."""
        dic = json.loads(json_struct)
        return cls(**dic)


class SessionBackend(metaclass=ABCMeta):
    """Backend for storing sessionDB data."""

    @abstractmethod
    def __setitem__(self, key: str, value: Dict[str, str]) -> None:
        """Store the session information under the session_id."""

    @abstractmethod
    def __getitem__(self, key: str) -> Dict[str, str]:
        """
        Retrieve the session information based os session_id.

        @raises KeyError when no key is found.
        """

    @abstractmethod
    def __delitem__(self, key: str) -> None:
        """Remove the stored session from storage."""

    @abstractmethod
    def __contains__(self, key: str) -> bool:
        """Test presence of key in storage."""

    @abstractmethod
    def get_by_uid(self, uid: str) -> List[str]:
        """Return session ids (keys) based on `uid` (internal user identifier)."""

    @abstractmethod
    def get_by_sub(self, sub: str) -> List[str]:
        """Return session ids based on `sub` (external user identifier)."""

    @abstractmethod
    def get(self, attr: str, val: str) -> List[str]:
        """Return session ids based on attribute name and value."""

    def get_client_ids_for_uid(self, uid: str) -> List[str]:
        """Return client ids that have a session for given uid."""
        return [self[sid]["client_id"] for sid in self.get_by_uid(uid)]

    def get_verified_logout(self, uid: str) -> Optional[str]:
        """Return logout verification key for given uid."""
        # Since all the sessions should be the same, we return the first one
        sids = self.get_by_uid(uid)
        if len(sids) == 0:
            return None
        _dict = self[sids[0]]
        if "verified_logout" not in _dict:
            return None
        return _dict["verified_logout"]

    def get_token_ids(self, uid: str) -> List[str]:
        """Return id_tokens for the given uid."""
        return [self[sid]["id_token"] for sid in self.get_by_uid(uid)]

    def is_revoke_uid(self, uid: str) -> bool:
        """Return if the session is revoked."""
        # We do not care which session it is - once revoked, al are revoked
        return any([self[sid]["revoked"] for sid in self.get_by_uid(uid)])

    def get_uid_by_sub(self, sub):
        """
        Should only be one so stop after the first is found.
        """
        for sid in self.get_by_sub(sub):
            return AuthnEvent.from_json(self[sid]["authn_event"]).uid
        return None

    def get_uid_by_sid(self, sid):
        return AuthnEvent.from_json(self[sid]["authn_event"]).uid

    def get_by_sub_and_(self, sub, key, val):
        for sid in self.get_by_sub(sub):
            try:
                if self[sid][key] == val:
                    return sid
            except KeyError:
                continue
        return None

    def update(self, key, attribute, value):
        """
        Updates information stored. If the key is not know a new entry will be
        constructed.

        :param key: Key to the database
        :param attribute: Attribute name
        :param value: Attribute value
        """
        if key not in self:
            self[key] = {attribute: value}
        else:
            item = self[key]
            item[attribute] = value
            self[key] = item


class DictSessionBackend(SessionBackend):
    """
    Simple implementation of `SessionBackend` based on dictionary.

    This should really not be used in production.
    """

    def __init__(self):
        """Create the storage."""
        self.storage = {}  # type: Dict[str, Dict[str, str]]

    def __setitem__(self, key: str, value: Dict[str, str]) -> None:
        """Store the session info in the storage."""
        self.storage[key] = value

    def __getitem__(self, key: str) -> Dict[str, str]:
        """Retrieve session information based on session id."""
        return self.storage[key]

    def __delitem__(self, key: str) -> None:
        """Delete the session info."""
        del self.storage[key]

    def __contains__(self, key: str) -> bool:
        return key in self.storage

    def get_by_sub(self, sub: str) -> List[str]:
        """Return session ids based on sub."""
        return [
            sid for sid, session in self.storage.items() if session.get("sub") == sub
        ]

    def get_by_uid(self, uid: str) -> List[str]:
        """Return session ids based on uid."""
        return [
            sid
            for sid, session in self.storage.items()
            if AuthnEvent.from_json(session["authn_event"]).uid == uid
        ]

    def get(self, attr: str, val: str) -> List[str]:
        """Return session ids based on attribute name and value."""
        return [
            sid for sid, session in self.storage.items() if session.get(attr) == val
        ]

    def get_uid_by_sub(self, sub):
        """Return User ids based on sub. Should only be one."""
        for sid, session in self.storage.items():
            if session.get("sub") == sub:
                return AuthnEvent.from_json(session["authn_event"]).uid
        return None

    def get_uid_by_sid(self, sid):
        return self.get_uid_by_sub(self.storage[sid]["sub"])

    def get_by_sub_and_(self, sub, key, val):
        """
        Given a subject identifier and a key/value pair return the Id of a session
        that matches those values.

        :param sub: Subjecty Identifier
        :param key: attribute name
        :param val: attribute value
        :return: Session identifier
        """
        for sid, session in self.storage.items():
            if session.get("sub") == sub and session.get(key) == val:
                return sid

    def update(self, key, attribute, value):
        """
        Updates information stored. If the key is not know a new entry will be
        constructed.

        :param key: Key to the database
        :param attribute: Attribute name
        :param value: Attribute value
        """
        if key not in self.storage:
            self.storage[key] = {attribute: value}
        else:
            item = self.storage[key]
            item[attribute] = value
            self.storage[key] = item


def session_update(db, key, attr, val):
    if isinstance(db, SessionBackend):
        db.update(key, attr, val)
    elif isinstance(db, dict):
        item = db[key]
        item[attr] = val
        db[key] = item
    else:
        raise ValueError("Unknown session database type")


def session_get(db, attr, val):
    """Return session ID based on attribute having value val"""
    if isinstance(db, SessionBackend):
        db.get(attr, val)
    elif isinstance(db, dict):
        for _key, _val in db.items():
            try:
                if _val[attr] == val:
                    return _key
            except KeyError:
                continue
        return None
    else:
        raise ValueError("Unknown session database type")


def session_extended_get(db, sub, attr, val):
    """Return session ID based on subject_id and attribute attr having value val"""
    if isinstance(db, SessionBackend):
        for sid in db.get_by_sub(sub):
            try:
                if db[sid][attr] == val:
                    return sid
            except KeyError:
                continue
        return None
    elif isinstance(db, dict):
        for _key, _val in db.items():
            try:
                if _val['sub'] == sub and _val[attr] == val:
                    return _key
            except KeyError:
                continue
        return None
    else:
        raise ValueError("Unknown session database type")


def session_set(db, attr, val):
    if isinstance(db, SessionBackend):
        db[attr] = val
    elif isinstance(db, dict):
        db[attr] = val
    else:
        raise ValueError("Unknown session database type")
