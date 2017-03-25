#!/bin/bash

cd /opt/dirg/src/pyoidc-master/examples/op/example_op/

if [ -f /opt/dirg/settings/settings.yaml ]; then
	SETTINGS=/opt/dirg/settings/settings.yaml
	echo "Using settings.yaml from volume"
else
        SETTINGS=settings.yaml.example
	echo "Using settings.yaml from example file"
fi

python src/run.py -b "${BASE_URL}" -p 8092 -d ${SETTINGS}
