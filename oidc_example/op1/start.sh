#!/bin/sh
./claims_provider.py -p 8093 -d cp_config.json &
./oc_server.py -p 8092 -d oc_config &
