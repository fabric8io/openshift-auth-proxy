# OpenShift Authentication Proxy
A reverse proxy that authenticates the request against OpenShift, retrieving
user information & setting the configured header with the appropriate details.

## Install
npm install -g openshift-auth-proxy

## Usage
```
Usage: openshift-auth-proxy [options]

Options:
  --listen-port              Port to listen on                                                           [default: 3000]
  --server-cert              Certificate file to use to listen for TLS                   [default: "secret/server-cert"]
  --server-key               Key file to use to listen for TLS                            [default: "secret/server-key"]
  --server-tlsopts-file      File containing JSON for proxy TLS options              [default: "secret/server-tls.json"]
  --backend                  Backend to proxy requests to once authenticated
  --use-backend-host-header  Change the host header to the backend URL                        [boolean] [default: false]
  --backend-ca               CA certificate file for validating the backend connection TLS (if needed)
                                                                                          [default: "secret/backend-ca"]
  --client-cert              Client certificate file for mutual TLS to the backend URL (if needed)
                                                                                         [default: "secret/client-cert"]
  --client-key               Client key file for mutual TLS to the backend URL (if needed)
                                                                                          [default: "secret/client-key"]
  --auth-mode                Proxy auth mode    [choices: "oauth2", "bearer", "mutual_tls", "dummy"] [default: "oauth2"]
  --mutual-tls-ca            CA cert file to use for validating TLS client certs under "mutual_tls" auth method
                                                                                           [default: "secret/mutual-ca"]
  --session-secret           File containing secret for encrypted session cookies under "oauth2" method
                                                                                      [default: "secret/session-secret"]
  --session-duration         Duration for encrypted session cookies                                   [default: 3600000]
  --session-active-duration  Active duration for encrypted session cookies                             [default: 300000]
  --session-ephemeral        Delete cookies on browser close                                   [boolean] [default: true]
  --callback-url             OAuth callback URL                                    [default: "/auth/openshift/callback"]
  --logout-redirect          URL to send user to after they log out from OAuth session                    [default: "/"]
  --oauth-id                 OAuth client ID
  --oauth-secret             File containing OAuth client secret                        [default: "secret/oauth-secret"]
  --public-master-url        Public master address for redirecting clients to
  --master-url               Internal master address proxy will authenticate against for oauth/bearer
                                                          [default: "https://kubernetes.default.svc.cluster.local:8443"]
  --master-ca                CA certificate(s) file to validate connection to the master   [default: "secret/master-ca"]
  --transform                Transform name(s) to apply to the request/response after authentication [choices: "
                             user_header", "token_header", "none"]                              [default: "user_header"]
  --user-header              Header for sending user name on the proxied request        [default: "X-Proxy-Remote-User"]
  --trust-remote-user        Use the user-header from the proxied request (if set) as the user for the backend request.
                                                                                                               [boolean]
  --debug                    Show extra debug information at startup and during operations                     [boolean]
  --help                     Show help                                                                         [boolean]

All of these parameters can be set via corresponding environment variables.

```
