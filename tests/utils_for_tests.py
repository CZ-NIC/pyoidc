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
