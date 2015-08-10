# OpenShift Authentication Proxy
A reverse proxy that authenticates the request against OpenShift, retrieving
user information & setting the configured header with the appopriate details.

## Install
npm install -g openshift-auth-proxy

## Usage
```
Usage: openshift-auth-proxy.js [options]

Options:
  --target                   Target to proxy to                       [required]
  --target-ca                CA used to valid target server
  --listen-port              Port to listen on        [required] [default: 3000]
  --user-header              Header to set the user name on the proxied request
                                             [required] [default: "REMOTE_USER"]
  --session-secret           Secret for encrypted session cookies
                                               [required] [default: "generated"]
  --session-duration         Duration for encrypted session cookies
                                                   [required] [default: 3600000]
  --session-active-duration  Active duration for encrypted session cookies
                                                    [required] [default: 300000]
  --callback-url             oAuth callback URL
                                [required] [default: "/auth/openshift/callback"]
  --client-id                OAuth client ID                          [required]
  --client-secret            OAuth client secret                      [required]
  --openshift-master         OpenShift master to authenticate against
                                                                      [required]
  --openshift-ca             CA certificate[s] to use                 [required]
  --tls-cert                 Certificate file to use to listen for TLS
                                                                      [required]
  --tls-key                  Key file to use to listen for TLS        [required]
  -h, --help                 Show help                                 [boolean]

copyright 2015
```
