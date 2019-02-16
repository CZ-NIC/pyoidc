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
echo "---Running oidc-provider-conformance-tests 'code'---"
npm run code || exit
echo "---Running oidc-provider-conformance-tests 'id_token'---"
npm run id_token || exit
echo "---Running oidc-provider-conformance-tests 'id_token+token'---"
npm run id_token+token || exit
echo "---Running oidc-provider-conformance-tests 'code+id_token'---"
npm run code+id_token || exit
echo "---Running oidc-provider-conformance-tests 'code+id_token+token'---"
npm run code+id_token+token || exit
echo "---Running oidc-provider-conformance-tests 'code+token'---"
npm run code+token || exit

cd /root/openid-client-conformance-tests
export ISSUER=https://rp-test:8080
export NODE_TLS_REJECT_UNAUTHORIZED=0
echo "---Running openid-client-conformance-tests 'non-profile'---"
npm run non-profile || exit
echo "---Running openid-client-conformance-tests 'basic'---"
npm run basic || exit
echo "---Running openid-client-conformance-tests 'config'---"
npm run config || exit
echo "---Running openid-client-conformance-tests 'dynamic'---"
npm run dynamic || exit
echo "---Running openid-client-conformance-tests 'id_token-implicit'---"
npm run id_token-implicit || exit
echo "---Running openid-client-conformance-tests 'id_token+token-implicit'---"
npm run id_token+token-implicit || exit
echo "---Running openid-client-conformance-tests 'code+id_token-hybrid'---"
npm run code+id_token-hybrid || exit
echo "---Running openid-client-conformance-tests 'code+token-hybrid'---"
npm run code+token-hybrid || exit
echo "---Running openid-client-conformance-tests 'code+id_token+token-hybrid'---"
npm run code+id_token+token-hybrid || exit
echo "---FINISHED---"
