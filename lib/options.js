var    parseDuration  = require('parse-duration');
var    yargs          = require('yargs');


yargs
  .usage('Usage: $0 [options]')
  .wrap(120)
  .options({
    backend: {
      describe: 'Backend to proxy requests to once authenticated',
      default: process.env.OAP_BACKEND_URL
    }, 'use-backend-host-header': {
      describe: 'Change the host header to the backend URL',
      type: 'boolean',
      default: false
    }, 'listen-port': {
      describe: 'Port to listen on',
      default: Number(process.env.OAP_PROXY_PORT || 3000)
    }, 'auth-mode': {
      describe: 'Proxy auth mode',
      choices:  ['oauth2', 'bearer', 'mutual_tls', 'dummy'],
      default: process.env.OAP_AUTH_MODE || 'oauth2'
    }, 'user-header': {
      describe: 'Header for sending user name on the proxied request',
      default: process.env.OAP_REMOTE_USER_HEADER || 'X-Proxy-Remote-User'
    }, 'session-secret': {
      describe: 'File containing secret for encrypted session cookies',
      default: process.env.OAP_SESSION_SECRET_FILE || 'secret/session-secret'
    }, 'session-duration': {
      describe: 'Duration for encrypted session cookies',
      default: parseDuration(process.env.OAP_SESSION_DURATION || '1h')
    }, 'session-active-duration': {
      describe: 'Active duration for encrypted session cookies',
      default: parseDuration(process.env.OAP_SESSION_ACTIVE_DURATION || '5m')
    }, 'session-ephemeral': {
      type: 'boolean',
      describe: 'Delete cookies on browser close',
      default: true
    }, 'callback-url': {
      describe: 'oAuth callback URL',
      default: process.env.OAP_CALLBACK_URL || '/auth/openshift/callback'
    }, 'client-id': {
      describe: 'OAuth client ID',
      default: process.env.OAP_CLIENT_ID
    }, 'client-secret': {
      describe: 'File containing OAuth client secret',
      default: process.env.OAP_CLIENT_SECRET_FILE || 'secret/client-secret'
    }, 'master-url': {
      describe: 'Internal master address proxy will authenticate against',
      default: process.env.OAP_MASTER_URL || 'https://kubernetes.default.svc.cluster.local:8443'
    }, 'public-master-url': {
      describe: 'Public master address for redirecting clients to',
      default: process.env.OAP_PUBLIC_MASTER_URL
    }, 'master-ca': {
      describe: 'CA certificate(s) file to validate connection to the master',
      default: process.env.OAP_MASTER_CA_FILE || 'secret/master-ca'
    }, 'proxy-cert': {
      describe: 'Certificate file to use to listen for TLS',
      default: process.env.OAP_PROXY_CERT_FILE || 'secret/proxy-cert'
    }, 'proxy-key': {
      describe: 'Key file to use to listen for TLS',
      default: process.env.OAP_PROXY_KEY_FILE || 'secret/proxy-key'
    }, 'proxy-tlsopts-file': {
      describe: 'File containing JSON for proxy TLS options',
      default: process.env.OAP_PROXY_TLS_FILE || 'secret/proxy-tls.json'
    }, 'mutual-tls-ca': {
      describe: 'CA cert file to use for validating TLS client certs under "mutual_tls" auth method',
      default: process.env.OAP_PROXY_CA_FILE || 'secret/proxy-ca'
    }, debug: {
      describe: 'Show extra debug information at startup and during operations',
      type: 'boolean',
      default: process.env.OAP_DEBUG
    }
  })
  .check(function(args) {
    // yargs#demand doesn't work if we also provide a default, so check for missing/invalid args here
    var errors = [];
    ["backend", "proxy-cert", "proxy-key", "proxy-tlsopts-file", "session-secret",
     "client-id", "client-secret", "master-url", "public-master-url", "master-ca",
     "mutual-tls-ca", "callback-url"].forEach( function(val) {
      if(args[val] == null || args[val].length == 0) {
        errors.push("No value specified for parameter " + val);
      }
    });
    if (isNaN(parseFloat(args['listen-port'])) || args['listen-port'] < 1) errors.push("Invalid listen-port specified");
    // Now report errors if present.
    if (errors.length > 0) throw('ERROR IN PARAMETERS:\n' + errors.join('\n'));
    return true
  })
  .help('help')
  .epilog('All of these parameters can be set via corresponding environment variables.')

var options =  yargs.argv;
module.exports = options
module.exports.logArgs = function(){
	for (var arg in yargs.argv) {
		console.log("%s", arg + ": " + yargs.argv[arg]);
	}
}

