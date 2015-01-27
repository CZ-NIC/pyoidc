from shelve import Shelf
import anydbm
import shelve

__author__ = 'danielevertsson'

class ShelfWrapper(Shelf):

    def __init__(self, filename, flag='c', protocol=None, writeback=False):
        self.filename = filename
        self.flag = flag

        Shelf.__init__(self, anydbm.open(filename, flag), protocol, writeback)

    def keys(self):
        dict = self._reopen_database()
        return dict.keys()

    def __len__(self):
        dict = self._reopen_database()
        return dict.__len__()

    def has_key(self, key):
        dict = self._reopen_database()
        return dict.has_key(key)

    def __contains__(self, key):
        dict = self._reopen_database()
        return dict.__contains__(key)

    def get(self, key, default=None):
        dict = self._reopen_database()
        return dict.get(key, default)

    def __getitem__(self, key):
        dict = self._reopen_database()
        return dict.__getitem__(key)

    def __setitem__(self, key, value):
        dict = self._reopen_database()
        dict.__setitem__(key, value)

    def __delitem__(self, key):
        dict = self._reopen_database()
        dict.__delitem__(key)

    def _reopen_database(self):
        return shelve.open(self.filename, writeback=True)

def open(filename, flag='c', protocol=None, writeback=False):
    """Open a persistent dictionary for reading and writing.

    The filename parameter is the base filename for the underlying
    database.  As a side-effect, an extension may be added to the
    filename and more than one file may be created.  The optional flag
    parameter has the same interpretation as the flag parameter of
    anydbm.open(). The optional protocol parameter specifies the
    version of the pickle protocol (0, 1, or 2).

    See the module's __doc__ string for an overview of the interface.
    """

    return ShelfWrapper(filename, flag, protocol, writeback)