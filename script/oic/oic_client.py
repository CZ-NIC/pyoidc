#!/usr/bin/env python

__author__ = 'rohe0002'

from oic.script import OIC
from oic.script import oic_operations
from oic.oic import Client
from oic.oic.consumer import Consumer
from oic.oic import message

cli = OIC(oic_operations, message, Client, Consumer)

cli.run()