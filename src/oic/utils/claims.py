__author__ = 'rolandh'


# noinspection PyUnusedLocal
class ClaimsMode(object):
    def __init__(self, user2mode):
        self.user2mode = user2mode

    def aggregate(self, uid, info=None):
        try:
            if self.user2mode[uid] == "aggregate":
                return True
        except KeyError:
            pass

        return False
