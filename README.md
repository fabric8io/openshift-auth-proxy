# OpenShift Authentication Proxy
A reverse proxy that authenticates the request against OpenShift, retrieving
user information & setting the configured header with the appopriate details.

## Install
npm install -g openshift-auth-proxy

## Usage
```
Usage: openshift-auth-proxy.js [options]

Options:
  --port                Port to listen on  [required] [default: 8080]
  --target              Target to proxy to  [required]
  --target-ca           CA used to valid target server
  --openshift-master    OpenShift master to authenticate against  [required]
  --openshift-ca        CA certificate[s] to use  [required]
  --server-certificate  Certificate file to use to listen for TLS
  --server-key          Key file to use to listen for TLS
  --header              Header to set the username on for the proxied request  [required] [default: "X-WEBAUTH-USER"]
  -h, --help            Show help  [boolean]

Examples:
  openshift-auth-proxy.js --target http://localhost:12345 --openshift-master https://localhost:8443 --openshift-ca /var/lib/openshift/openshift.local.config/master/ca.crt  proxy requests to http://localhost:12345, authenticating against openshift at https://localhost:8443 with CA certificate /var/lib/openshift/openshift.local.config/master/ca/crt

copyright 2015
```
