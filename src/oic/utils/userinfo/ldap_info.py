import ldap
from ldap import SCOPE_SUBTREE

from oic.utils.userinfo import UserInfo

__author__ = 'rolandh'


class UserInfoLDAP(UserInfo):
    def __init__(self, uri, base, filter_pattern, scope=SCOPE_SUBTREE,
                 tls=False, user="", passwd="", attr=None, attrsonly=False):
        UserInfo.__init__(self, None)
        self.ldapuri = uri
        self.base = base
        self.filter_pattern = filter_pattern
        self.scope = scope
        self.tls = tls
        self.attr = attr
        self.attrsonly = attrsonly
        self.ld = ldap.initialize(uri)
        self.ld.protocol_version = ldap.VERSION3
        self.ld.simple_bind_s(user, passwd)

    def __getitem__(self, item):
        _filter = self.filter_pattern % item
        arg = [self.base, self.scope, _filter, self.attr, self.attrsonly]
        res = self.ld.search_s(*arg)
        if len(res) == 1:
            # should only be one entry and the information per entry is
            # the tuple (dn, ava)
            return res[0][1]
        else:
            return {}