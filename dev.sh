#!/bin/bash

nodemon openshift-auth-proxy.js \
  --tls-cert test-cert.pem \
  --tls-key test-key.pem \
  --openshift-master https://localhost:8443 \
  --openshift-ca /var/lib/openshift/openshift.local.config/master/ca.crt \
  --client-id integration-services \
  --client-secret 12345 \
  $@
