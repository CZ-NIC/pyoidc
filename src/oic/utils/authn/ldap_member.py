import logging
from oic.utils.userinfo.ldap_info import UserInfoLDAP
from oic.oic.message import UserInfoClaim

__author__ = 'haho0032'

logger = logging.getLogger(__name__)


class UserLDAPMemberValidation(UserInfoLDAP):
    CONST_LDAPMEMBER = 'eduPersonAffiliation'
    CONST_VALIDFIELDS = ['employee', 'staff', 'student']



    def __init__(self,verifyAttr, verifyAttrValid, **kwargs):
        UserInfoLDAP.__init__(self, **kwargs)
        self.verifyAttr = verifyAttr
        self.verifyAttrValid = verifyAttrValid

    def __call__(self, userid):
        uic = {self.verifyAttr: None}
        result = UserInfoLDAP.__call__(self, userid, UserInfoClaim(claims=uic))
        if self.verifyAttr in result:
            for field in result[self.verifyAttr]:
                if field in self.verifyAttrValid:
                    return True
        return False
