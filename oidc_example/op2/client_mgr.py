#!/usr/bin/env python
import json

from oic.utils.client_management import CDB

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('-l', dest='list', action='store_true')
    parser.add_argument('-a', dest='add')
    parser.add_argument('-d', dest='delete')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # Client data base
    cdb = CDB(args.config)

    if args.list:
        for key, val in cdb.items():
            print('{}:{}'.format(key, val['redirect_uris']))

    if args.add:
        fp = open(args.add)
        spec = json.load(fp)
        cli_info = cdb.create(**spec)
        print(cli_info)

    if args.delete:
        del cdb[args.delete]
