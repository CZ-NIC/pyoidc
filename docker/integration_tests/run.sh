#!/bin/bash

#TRAVIS and CI variables make the test suite think that it's running in a travis pipeline
#which makes it start puppeteer with the --no-sandbox option, otherwise you get a no usable 
#sandbox error from chrome and it won't start
export TRAVIS=TRAVIS
export CI=CI

export TEST_PORT=60003
export TEST_HOSTNAME=op-test
export TEST_PROTOCOL=https
export TAG=default
export NODE_TLS_REJECT_UNAUTHORIZED=0

cd /root/oidc-provider-conformance-tests
export ISSUER=https://op:4433
echo "---Running oidc-provider-conformance-tests 'code' and 'id_token'---"
concurrently -- "npm:code" "npm:id_token" || exit
echo "---Running oidc-provider-conformance-tests 'id_token+token' and 'code+id_token'---"
concurrently -- "npm:id_token+token" "npm:code+id_token" || exit
echo "---Running oidc-provider-conformance-tests 'code+id_token+token' and 'code+token'---"
concurrently -- "npm:code+id_token+token" "npm:code+token" || exit

cd /root/openid-client-conformance-tests
export ISSUER=https://rp-test:8080
export NODE_TLS_REJECT_UNAUTHORIZED=0
echo "---Running openid-client-conformance-tests---"
npm run test || exit
echo "---FINISHED---"
