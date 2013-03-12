#!/bin/bash

cwd=$(dirname $0)

export PYTHONPATH="${cwd}/src"

$@
