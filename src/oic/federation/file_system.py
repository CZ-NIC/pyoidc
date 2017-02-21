import logging
import os
import time

logger = logging.getLogger(__name__)


class FileSystem(object):
    def __init__(self, fdir, key_conv=None, value_conv=None):
        self.fdir = fdir
        self.fmtime = {}
        self.db = {}
        self.key_conv = key_conv or {}
        self.value_conv = value_conv or {}

    def __getitem__(self, item):
        try:
            item = self.key_conv['in'](item)
        except KeyError:
            pass

        if self.is_changed(item):
            logger.info("File content change in {}".format(item))
            fname = os.path.join(self.fdir, item)
            self.db[item] = self._read_info(self.value_conv['from'](fname))

        return self.db[item]

    def __setitem__(self, key, value):
        """

        :param key: Identifier
        :param value: Most be a string
        :return:
        """

        if not os.path.isdir(self.fdir):
            os.makedirs(self.fdir, exist_ok=True)

        try:
            _key = self.key_conv['to'](key)
        except KeyError:
            _key = key

        fname = os.path.join(self.fdir, _key)
        fp = open(fname, 'w')
        try:
            fp.write(self.value_conv['to'](value))
        except KeyError:
            fp.write(value)
        fp.close()

        self.db[key] = value
        self.fmtime[key] = self.get_mtime(fname)

    def keys(self):
        self.sync()
        res = []
        for k in self.db.keys():
            try:
                res.append(self.key_conv['from'](k))
            except KeyError:
                res.append(k)
        return res

    @staticmethod
    def get_mtime(fname):
        try:
            mtime = os.stat(fname).st_mtime
        except OSError:
            # The file might be right in the middle of being written
            # so sleep
            time.sleep(1)
            mtime = os.stat(fname).st_mtime

        return mtime

    def is_changed(self, item):
        fname = os.path.join(self.fdir, item)
        if os.path.isfile(fname):
            mtime = self.get_mtime(fname)

            try:
                _ftime = self.fmtime[item]
            except KeyError:  # Never been seen before
                self.fmtime[item] = mtime
                return True

            if mtime > _ftime:  # has changed
                self.fmtime[item] = mtime
                return True
            else:
                return False
        else:
            logger.error('Could not access {}'.format(fname))
            raise KeyError(item)

    def _read_info(self, fname):
        if os.path.isfile(fname):
            try:
                info = open(fname, 'r').read()
                try:
                    info = self.value_conv['from'](info)
                except KeyError:
                    pass
                return info
            except Exception as err:
                logger.error(err)
                raise
        else:
            logger.error('No such file: {}'.format(fname))
        return None

    def sync(self):
        if not os.path.isdir(self.fdir):
            raise ValueError('No such directory: {}'.format(self.fdir))
        for f in os.listdir(self.fdir):
            fname = os.path.join(self.fdir, f)
            if f in self.fmtime:
                if self.is_changed(f):
                    self.db[f] = self._read_info(fname)
            else:
                mtime = self.get_mtime(fname)
                self.db[f] = self._read_info(fname)
                self.fmtime[f] = mtime

    def items(self):
        self.sync()
        res = {}
        for k, v in self.db.items():
            try:
                res[(self.key_conv['from'](k))] = v
            except KeyError:
                res[k] = v
        return res
