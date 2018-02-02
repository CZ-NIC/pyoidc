"""Client managament databases."""
import requests
from six.moves.urllib.parse import quote
from six.moves.urllib.parse import urljoin

from oic.oauth2.exception import NoClientInfoReceivedError


class BaseClientDatabase(object):
    """
    Base implementation for Client management database.

    Custom Client databases should derive from this class.
    They must implement the following methods:
    * ``__getitem__(self, key)``
    * ``__setitem__(self, key, value)``
    * ``__delitem__(self, key)``
    * ``keys(self)``
    * ``items(self)``
    """

    def __init__(self):
        """Perform initialization of storage. Derived classes may override."""

    def __getitem__(self, key):
        """Retrieve an item by a key. Raises KeyError if item not found."""
        raise NotImplementedError

    def get(self, key, default=None):
        """Retrieve an item by a key. Return default if not found."""
        try:
            return self[key]
        except KeyError:
            return default

    def __setitem__(self, key, value):
        """Set key with value."""
        raise NotImplementedError

    def __delitem__(self, key):
        """Remove key from database."""
        raise NotImplementedError

    def __contains__(self, key):
        """Return True if key is contained in the database."""
        try:
            self[key]
        except KeyError:
            return False
        else:
            return True

    def keys(self):
        """Return all contained keys."""
        raise NotImplementedError

    def items(self):
        """Return list of all contained items."""
        raise NotImplementedError

    def __len__(self):
        """Return number of contained keys."""
        return len(self.keys())


class DictClientDatabase(BaseClientDatabase):
    """Simple implementation of client database with a dict as storage."""

    def __init__(self):
        """Initialize the storage."""
        self.cdb = {}

    def __getitem__(self, key):
        """Retrieve an item and return its value. Raises KeyError if item not found."""
        return self.cdb[key]

    def __setitem__(self, key, value):
        """Set item with value."""
        self.cdb[key] = value

    def __delitem__(self, key):
        """Remove key from database."""
        del self.cdb[key]

    def keys(self):
        """Return all contained keys."""
        return self.cdb.keys()

    def items(self):
        """Return list of all contained items."""
        return self.cdb.items()


class MDQClient(BaseClientDatabase):
    """Implementation of remote client database."""

    def __init__(self, url):
        """Set the remote storage url."""
        self.url = url
        self.headers = {'Accept': 'application/json', 'Accept-Encoding': 'gzip'}

    def __getitem__(self, item):
        mdx_url = urljoin(self.url, 'entities/{}'.format(quote(item, safe='')))
        response = requests.get(mdx_url, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise NoClientInfoReceivedError("{} {}".format(response.status_code, response.reason))

    def __setitem__(self, item, value):
        """Remote management is readonly."""
        raise RuntimeError('MDQClient is readonly.')

    def __delitem__(self, item):
        """"Remote management is readonly."""
        raise RuntimeError('MDQClient is readonly.')

    def keys(self):
        """Get all registered entitites."""
        mdx_url = urljoin(self.url, 'entities')
        response = requests.get(mdx_url, headers=self.headers)
        if response.status_code == 200:
            return [item['client_id'] for item in response.json()]
        else:
            raise NoClientInfoReceivedError("{} {}".format(response.status_code, response.reason))

    def items(self):
        """Geting all registered entities."""
        mdx_url = urljoin(self.url, 'entities')
        response = requests.get(mdx_url, headers=self.headers)
        if response.status_code == 200:
            return response.json()
        else:
            raise NoClientInfoReceivedError("{} {}".format(response.status_code, response.reason))
