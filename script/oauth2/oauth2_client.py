#!/usr/bin/env python

__author__ = 'rohe0002'

from oic.script import OAuth2
from oic.script import oauth2_operations
from oic.oauth2 import Client
from oic.oauth2 import message

cli = OAuth2(oauth2_operations, message, Client)

cli.run()