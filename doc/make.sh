#!/bin/sh
rm -f oic*
sphinx-apidoc -F -o ../doc/ ../src/oic
make clean
make html