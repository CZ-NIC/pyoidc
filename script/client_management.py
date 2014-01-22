#!/usr/bin/env python
import shelve
import urllib
import urlparse
import argparse
import sys
from oic.oic.provider import secret
from oic.oauth2 import rndstr

__author__ = 'rolandh'


def pack_redirect_uri(redirect_uris):
    ruri = []
    for uri in redirect_uris:
        if urlparse.urlparse(uri).fragment:
            print >> sys.stderr, "Faulty redirect uri, contains fragment"
        base, query = urllib.splitquery(uri)
        if query:
            ruri.append((base, urlparse.parse_qs(query)))
        else:
            ruri.append((base, query))

    return ruri


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

    def create(self, redirect_uris=None, policy_uri="", logo_uri=""):
        if redirect_uris is None:
            print 'Enter redirect_uris one at the time, end with a blank line: '
            redirect_uris = []
            while True:
                redirect_uri = raw_input('?: ')
                if redirect_uri:
                    redirect_uris.append(redirect_uri)
                else:
                    break
        if not policy_uri:
            policy_uri = raw_input("Enter policy_uri or just return: ")
        if not logo_uri:
            logo_uri = raw_input("Enter logo_uri or just return: ")

        client_id = rndstr(12)
        while client_id in self.cdb:
            client_id = rndstr(12)

        client_secret = secret(self.seed, client_id)

        self.cdb[client_id] = {
            "client_secret": client_secret,
            "client_id": client_id,
            "redirect_uris": pack_redirect_uri(redirect_uris),
            "policy_uri": policy_uri,
            "logo_uri": logo_uri,
        }

        return self.cdb[client_id]

    def __delitem__(self, key):
        del self.cdb[key]

    def __setitem__(self, key, value):
        self.cdb[key] = eval(value)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', dest='list', action='store_true',
                        help="list all client_ids")
    parser.add_argument('-d', dest='delete', action='store_true',
                        help="delete the entity with the given client_id")
    parser.add_argument('-c', dest='create', action='store_true',
                        help=("create a new client, returns the stored" ""
                              "information"))
    parser.add_argument('-s', dest='show', action='store_true',
                        help=("show information connected to a specific"
                              "client_id"))
    parser.add_argument('-i', dest='client_id',
                        help="a client_id on which to do an action")
    parser.add_argument('-r', dest='replace',
                        help=("information that should replace what's there"
                              "about a specific client_id"))
    parser.add_argument(dest="filename")
    args = parser.parse_args()

    cdb = CDB(args.filename)
    if args.list:
        print cdb.keys()
    elif args.client_id:
        if args.delete:
            del cdb[args.client_id]
        elif args.show:
            print cdb[args.client_id]
        elif args.replace:
            cdb[args.client_id] = args.replace
    elif args.create:
        print cdb.create()
    elif args.delete or args.show or args.replace:
        print "You have to specify a client_id !"