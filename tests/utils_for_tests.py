from six.moves.urllib.parse import urlparse, parse_qs

__author__ = "@maennelpaennel"


def _eq(l1, l2):
    return set(l1) == set(l2)


class URLObject(object):
    host = ''
    resource = ''
    arguments = set()

    @classmethod
    def create(klass, address):
        url_obj = klass()
        url_obj.set_by_string(address)
        return url_obj

    def __init__(self, host='', resource='', arguments=None):
        self.host = host
        self.resource = resource
        self.arguments = arguments or set()

    def __eq__(self, other):
        return self.host == other.host and self.resource == other.resource \
               and self.arguments == other.arguments

    def set_by_string(self, address):
        """
        address has the following format
        "<protocol>://<host>/<resource>?<argname>=<argval>&..."
        """
        address_splits = address.split('?', 1)
        if len(address_splits) == 1:
            host_resource = address_splits[0]
            arguments_str = ''
        else:
            host_resource = address_splits[0]
            arguments_str = address_splits[1]
        self.arguments = set(arguments_str.split('&'))
        host_res_splits = host_resource.split('://', 1)
        if len(host_res_splits) == 1:
            host_resource = host_res_splits[0]
            prefix = None
        else:
            host_resource = host_res_splits[0]
            prefix = host_res_splits[1]
        host_res_splits = host_resource.split('/', 1)
        if len(host_res_splits) == 1:
            host = None
            resource = host_res_splits[0]
        else:
            host = host_res_splits[0]
            resource = host_res_splits[1]
        if host:
            self.host = host
            if prefix:
                self.host = "%s://%s" % (prefix, host)
        self.resource = resource


def url_compare(url1, url2):
    url1 = urlparse(url1)
    url2 = urlparse(url2)

    if url1.scheme != url2.scheme:
        return False
    if url1.netloc != url2.netloc:
        return False
    if url1.path != url2.path:
        return False
    if not query_string_compare(url1.query, url2.query):
        return False
    if not query_string_compare(url1.fragment, url2.fragment):
        return False

    return True


def query_string_compare(query_str1, query_str2):
    return parse_qs(query_str1) == parse_qs(query_str2)
