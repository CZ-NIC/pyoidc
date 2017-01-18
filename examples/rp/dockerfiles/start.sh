#!/bin/bash

cd /opt/dirg/src/pyoidc-master/examples/rp/example_rp/

if [ -f /opt/dirg/settings/settings.yaml ]; then
	SETTINGS=/opt/dirg/setting/settings.yaml
	echo "Using settings.yaml from volume"
else
	SETTINGS=settings.yaml.example
	echo "Using settings.yaml from example file"
fi

python src/rp.py -b "${BASE_URL}" -p 8666 ${SETTINGS}
