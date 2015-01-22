import json

import requests
import jwkest


class NoClientInfoReceived(Exception):
    pass


class MDXClient(object):
    def __init__(self, url):
        self.url = url

    def __getitem__(self, item):
        mdx_url = "{}/clients/{}".format(self.url, item)
        response = requests.request("GET", mdx_url, headers={'Accept': 'application/json',
                                                             'Accept-Encoding': 'gzip'})
        if response.status_code == 200:
            unpacked_jwt = jwkest.unpack(response.text.encode("utf-8"))
            client_info = json.loads(unpacked_jwt[1])
            return client_info
        else:
            raise NoClientInfoReceived("{} {}".format(response.status_code, response.reason))