#!/usr/bin/env python
import shelve
import argparse
from oic.oic.provider import secret
from oic.oauth2 import rndstr

__author__ = 'rolandh'


class CDB(object):
    def __init__(self, filename):
        self.cdb = shelve.open(filename, writeback=True)
        self.seed = rndstr(32)

    def __getitem__(self, item):
        return self.cdb[item]

    def keys(self):
        return self.cdb.keys()

    def items(self):
        return self.cdb.items()

    def create(self, redirect_uris=None, policy_url="", logo_url=""):
        if redirect_uris is None:
            print 'Enter redirect_uris one at the time, end with a blank line: '
            redirect_uris = []
            while True:
                redirect_uri = raw_input('?: ')
                if redirect_uri:
                    redirect_uris.append(redirect_uri)
                else:
                    break
        if not policy_url:
            policy_url = raw_input("Enter policy_url or just return: ")
        if not logo_url:
            logo_url = raw_input("Enter logo_url or just return: ")

        client_id = rndstr(12)
        while client_id in self.cdb:
            client_id = rndstr(12)

        client_secret = secret(self.seed, client_id)

        self.cdb[client_id] = {
            "client_secret": client_secret,
            "client_id": client_id,
            "redirect_uris": redirect_uris,
            "policy_url": policy_url,
            "logo_url": logo_url,
        }

        return client_id, client_secret

    def __delitem__(self, key):
        del self.cdb[key]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', dest='list', action='store_true')
    parser.add_argument('-d', dest='delete')
    parser.add_argument('-c', dest='create', action='store_true')
    parser.add_argument('-s', dest='show')
    #parser.add_argument('-A', dest='authn_as', default="")
    #parser.add_argument('-P', dest='provider_conf')
    parser.add_argument(dest="filename")
    args = parser.parse_args()

    cdb = CDB(args.filename)
    if args.list:
        print cdb.keys()
    elif args.delete:
        del cdb[args.delete]
    elif args.create:
        print cdb.create()
    elif args.show:
        print cdb[args.show]
