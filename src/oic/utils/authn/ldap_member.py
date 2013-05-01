import logging
from oic.utils.userinfo.ldap_info import UserInfoLDAP

__author__ = 'haho0032'

logger = logging.getLogger(__name__)


class UserLDAPMemberValidation(UserInfoLDAP):
    CONST_LDAPMEMBER = 'eduPersonScopedAffiliation;x-guise-anst2'
    CONST_VALIDFIELDS = ['employee@umu.se', 'staff@umu.se', 'member@umu.se']

    def __init__(self,ldap_member, valid_fields, **kwargs):
        UserInfoLDAP.__init__(self, **kwargs)
        self.ldap_member = ldap_member
        self.valid_fields = valid_fields

    def __call__(self, userid, **kwargs):
        result = UserInfoLDAP.__call__(self, userid)
        if self.ldap_member in result:
            for field in result[self.ldap_member]:
                if field in self.valid_fields:
                    return True
        return False
