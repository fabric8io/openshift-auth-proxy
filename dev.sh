#!/bin/bash

# This script does some setup for development use:
# sh dev.sh --master-url=...

if [[ ! -d ./secret ]]; then
	cp -r ./secret.example ./secret
fi
# generally need the master CA too
if [[ ! -e ./secret/master-ca ]]; then
	echo "copy your master CA file to ./secret/master-ca to use this script"
	exit 1
fi

# nodemon probably won't be in the proxy container but you'll
# want to install it for easy development work.
nodemon openshift-auth-proxy.js \
  --use-backend-host-header \
  --debug \
  --client-id integration-proxy \
  $@

# some args you'll need to fill in yourself:
# --backend http://localhost:8080/ \
# --master-url https://internal.example.com:8443 \
# --public-master-url https://external.example.com:8443 \
