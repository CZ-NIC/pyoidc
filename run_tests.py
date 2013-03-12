#!/usr/bin/env python

# Imports for appending dirs to PYTHONPATH
import os
import sys

import pytest

# Adding to PYTHONPATH
pwd = os.path.abspath(os.path.dirname(__file__))

sys.path.insert(0,os.path.join(pwd,'src'))

# Running tests
if '__main__' == __name__:
    pytest.main(' '.join(sys.argv[1:]))
