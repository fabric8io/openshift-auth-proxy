#!/bin/bash

# set or override any args:
# sh dev.sh --master-url=...

if [[ ! -d ./secret ]]; then
	cp -r ./secret.example ./secret
fi
# need the master CA too
if [[ ! -e ./secret/master-ca ]]; then
	echo "copy your master CA file to ./secret/master-ca to use this script"
	exit 1
fi

node openshift-auth-proxy.js \
  --master-url https://localhost:8443 \
  --public-master-url https://localhost:8443 \
  --client-id integration-proxy \
  $@
