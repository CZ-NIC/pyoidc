import logging
from oic.utils.userinfo.ldap_info import UserInfoLDAP

__author__ = 'haho0032'

logger = logging.getLogger(__name__)


class UserLDAPMemberValidation(UserInfoLDAP):

    def __init__(self, verifyAttr=None, verifyAttrValid=None, **kwargs):
        UserInfoLDAP.__init__(self, **kwargs)
        self.verifyAttr = verifyAttr
        self.verifyAttrValid = verifyAttrValid

    def __call__(self, userid, **kwargs):
        result = UserInfoLDAP.__call__(self, userid, None, False)
        if self.verifyAttr in result:
            for field in result[self.verifyAttr]:
                if field in self.verifyAttrValid:
                    return True
        logger.warning(userid + "tries to use the service with the values " + result)
        return False
