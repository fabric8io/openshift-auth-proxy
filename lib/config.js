var fs             = require('fs'),
    https          = require('https'),
    urljoin        = require('url-join'),
    parseDuration  = require('parse-duration');

var config = require('yargs')
  .usage('Usage: $0 [options]')
  .wrap(120)
  .options({
    'listen-port': {
      describe: 'Port to listen on',
      default: Number(process.env.OAP_SERVER_PORT || 3000)
    }, 'server-cert': {
      describe: 'Certificate file to use to listen for TLS',
      default: process.env.OAP_SERVER_CERT_FILE || 'secret/server-cert'
    }, 'server-key': {
      describe: 'Key file to use to listen for TLS',
      default: process.env.OAP_SERVER_KEY_FILE || 'secret/server-key'
    }, 'server-tlsopts-file': {
      describe: 'File containing JSON for proxy TLS options',
      default: process.env.OAP_SERVER_TLS_FILE || 'secret/server-tls.json'
    }, 'backend': {
      describe: 'Backend to proxy requests to once authenticated',
      default: process.env.OAP_BACKEND_URL
    }, 'use-backend-host-header': {
      describe: 'Change the host header to the backend URL',
      type: 'boolean',
      default: false
    }, 'backend-ca': {
      describe: 'CA certificate file for validating the backend connection TLS (if needed)',
      default: process.env.OAP_CLIENT_CERT_FILE || 'secret/backend-ca'
    }, 'client-cert': {
      describe: 'Client certificate file for mutual TLS to the backend URL (if needed)',
      default: process.env.OAP_CLIENT_CERT_FILE || 'secret/client-cert'
    }, 'client-key': {
      describe: 'Client key file for mutual TLS to the backend URL (if needed)',
      default: process.env.OAP_CLIENT_KEY_FILE || 'secret/client-key'
    }, 'auth-mode': {
      describe: 'Proxy auth mode',
      choices:  ['oauth2', 'bearer', 'mutual_tls', 'dummy'],
      default: process.env.OAP_AUTH_MODE || 'oauth2'
    }, 'mutual-tls-ca': {
      describe: 'CA cert file to use for validating TLS client certs under "mutual_tls" auth method',
      default: process.env.OAP_SERVER_CA_FILE || 'secret/mutual-ca'
    }, 'session-secret': {
      describe: 'File containing secret for encrypted session cookies under "oauth2" method',
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
      describe: 'OAuth callback URL',
      default: process.env.OAP_CALLBACK_URL || '/auth/openshift/callback'
    }, 'logout-redirect': {
      describe: 'URL to send user to after they log out from OAuth session',
      default: process.env.OAP_LOGOUT_REDIRECT || '/'
    }, 'oauth-id': {
      describe: 'OAuth client ID',
      default: process.env.OAP_OAUTH_ID
    }, 'oauth-secret': {
      describe: 'File containing OAuth client secret',
      default: process.env.OAP_OAUTH_SECRET_FILE || 'secret/oauth-secret'
    }, 'public-master-url': {
      describe: 'Public master address for redirecting clients to',
      default: process.env.OAP_PUBLIC_MASTER_URL
    }, 'master-url': {
      describe: 'Internal master address proxy will authenticate against for oauth/bearer',
      default: process.env.OAP_MASTER_URL || 'https://kubernetes.default.svc.cluster.local:8443'
    }, 'master-ca': {
      describe: 'CA certificate(s) file to validate connection to the master',
      default: process.env.OAP_MASTER_CA_FILE || 'secret/master-ca'
    }, 'transform': {
      // note: would like to be able to specify multiple in env var, but yargs.choices() does not validate input as comma-separated array
      describe: 'Transform name(s) to apply to the request/response after authentication [choices: "user_header", "token_header", "none"]',
      default: process.env.OAP_TRANSFORM || 'user_header,token_header'
    }, 'user-header': {
      describe: 'Header for sending user name on the proxied request',
      default: process.env.OAP_REMOTE_USER_HEADER || 'X-Proxy-Remote-User'
    }, 'trust-remote-user': {
      describe: 'Use the user-header from the proxied request (if set) as the user for the backend request.',
      type: 'boolean',
      default: process.env.OAP_TRUST_REMOTE_USER
    }, debug: {
      describe: 'Show extra debug information at startup and during operations',
      type: 'boolean',
      default: process.env.OAP_DEBUG
    }
  })
  .check(function(args) {
    // yargs#demand doesn't complain on empty env var default; check for missing/invalid args here
    var errors = [];
    ['backend', 'server-cert', 'server-key', 'server-tlsopts-file', 'mutual-tls-ca'].forEach( function(val) {
      if(args[val] == null || args[val].length === 0) {
        errors.push('No value specified for parameter ' + val);
      }
    });
    if (args['auth-mode'] === 'oauth2') {
      ['oauth-id', 'oauth-secret', 'master-url', 'public-master-url', 'master-ca', 'callback-url'].forEach( function(val) {
        if(args[val] == null || args[val].length === 0) {
          errors.push('No value specified for oauth2 parameter ' + val);
        }
      });
    }
    if (args['auth-mode'] === 'bearer') {
      ['master-url', 'master-ca'].forEach( function(val) {
        if(args[val] == null || args[val].length === 0) {
          errors.push('No value specified for "bearer" parameter ' + val);
        }
      });
    }
    if (args['auth-mode'] === 'mutual_tls' &&
       (args['mutual-tls-ca'] == null || args['mutual-tls-ca'].length === 0))
         errors.push('No value specified for "mutual_tls" parameter "mutual-tls-ca"');
    if (args['client-key'] && !args['client-cert'])
      errors.push('Specified client-key without client-cert');
    if (args['client-cert'] && !args['client-key'])
      errors.push('Specified client-cert without client-key');
    if (isNaN(parseFloat(args['listen-port'])) || args['listen-port'] < 1)
      errors.push('Invalid listen-port specified');
    (typeof(args.transform) === 'string'
      ? args.transform.split(',')
      : args.transform).
	forEach(function(transform) {
          if (['user_header', 'token_header', 'none'].indexOf(transform) === -1)
            errors.push('Unknown transform specified: ' + transform);
        });
    // Now report errors if present.
    if (errors.length > 0) throw('ERROR IN PARAMETERS:\n' + errors.join('\n'));
    return true
  })
  .help('help')
  .epilog('All of these parameters can be set via corresponding environment variables.')
  .argv;

// provide handy method for a debug log.
config.debugLog = function() {
  if (this.debug) console.log.apply(console, arguments)
}

//
// read in all the files with secrets, keys, certs
//
var files = {};
switch (config['auth-mode']) {
  case 'oauth2':
    // look for an oauth secret -- crash if not there
    files.oauthSecret = fs.readFileSync(config['oauth-secret'], 'utf8').
	                   replace(/(\n|\r)/gm,''); // newlines can mismatch secret
    try { // ok if missing, we will generate
      files.sessionSecret = fs.readFileSync(config['session-secret'], 'utf8');
    } catch(err) {
      console.error('error reading session secret: %s', JSON.stringify(e));
    } finally { // just ignore if the file is not there
      if (files.sessionSecret == null) {
        console.error('generating session secret (will not work with scaled service)');
        files.sessionSecret = require('base64url')(require('crypto').randomBytes(256)).substring(0, 256);
      }
    };
    // don't break, do both.
  case 'bearer': // and oauth2 as well:
    // ensure we validate connections to master w/ master CA.
    // technically this might not be required, but passport fails
    // silently if it *is* needed and is not present.
    var cas = https.globalAgent.options.ca || [];
    cas.push(fs.readFileSync(config['master-ca'], 'utf8'));
    https.globalAgent.options.ca = cas;
    break;
  case 'mutual_tls':
    try {
      files.mutualTlsCa = fs.readFileSync(config['mutual-tls-ca'], 'utf8');
    } catch(err) {
        throw 'No CA read for mutual TLS. Looked in: ' + config['mutual-tls-ca'];
    }
    break;
};

//
// optional TLS overrides (ciphersuite etc)
//
try {
  files.serverTLS = fs.readFileSync(config['server-tlsopts-file'], 'utf8');
  config.debugLog('Read TLS opts from %s: %s', config['server-tlsopts-file'], files.serverTLS);
  files.serverTLS = eval(files.serverTLS);
  if (files.serverTLS == null || ! typeof files.serverTLS === 'object') {
    throw('TLS opts file did not evaluate to an object');
  }
} catch(e) {
  console.error('Could not read TLS opts from %s; error was: %s', config['server-tlsopts-file'], e);
  files.serverTLS = {};
} finally {
  files.serverTLS['key'] = fs.readFileSync(config['server-key'], 'utf8');
  files.serverTLS['cert'] = fs.readFileSync(config['server-cert'], 'utf8');
  config.debugLog('in finally, serverTLS is:', files.serverTLS);
}

//
// read provided CA/client cert for secured backend connection
//
if ( config['backend'].indexOf('https:') === 0) {
  var backendAgentOpts = {};
  if (config['backend-ca']) backendAgentOpts['ca'] = fs.readFileSync(config['backend-ca'], 'utf8');
  if (config['client-key']) backendAgentOpts['key'] = fs.readFileSync(config['client-key'], 'utf8');
  if (config['client-cert']) backendAgentOpts['cert'] = fs.readFileSync(config['client-cert'], 'utf8');
  config.backendAgent = new https.Agent(backendAgentOpts);
}

//
// Display what we got, for debug purposes
//
if(config.debug) {
  console.log('config values passed in:');
  var arg;
  for (arg in config) {
    console.log('%s', arg + ': ' + config[arg]);
  }
  ['sessionSecret', 'oauthSecret', 'mutualTlsCa', 'serverTLS'].forEach( function(val) {
    console.log('%s: ', val, files[val]);
  })
}

// Some universal config values:
//
// where to get OpenShift user information for current auth
config.openshiftUserUrl = urljoin(config['master-url'], '/oapi/v1/users/~');
// make sure transforms is an array
config.transforms = typeof(config.transform) === 'string' ? config.transform.split(',') : config.transform;
// hang the files on the config
config.files = files;

module.exports = config;

