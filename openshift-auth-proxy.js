#!/usr/bin/env node

var express        = require('express'),
    sessions       = require('client-sessions'),
    passport       = require('passport'),
    OAuth2Strategy = require('passport-oauth2'),
    BearerStrategy = require('passport-http-bearer'),
    httpProxy      = require('http-proxy'),
    https          = require('https'),
    urljoin        = require('url-join'),
    request        = require('request'),
    morgan         = require('morgan'),
    parseDuration  = require('parse-duration'),
    fs             = require('fs');

var argv = require('yargs')
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
  .argv;

// ---------------------- config --------------------------

//
// read in all the files with secrets, keys, certs
//
var sessionSecret;
try {
  sessionSecret = fs.readFileSync(argv['session-secret'], "utf8");
} catch(err) {
  console.error("error reading session secret: %s", JSON.stringify(e));
} finally { // just ignore if the file is not there
  if (sessionSecret == null ) {
    console.error("generating session secret (will not work with scaled service)");
    sessionSecret = require('base64url')(require('crypto').randomBytes(256)).substring(0, 256);
  }
};
var clientSecret = fs.readFileSync(argv['client-secret'], "utf8").replace(/(\n|\r)/gm,"");
var masterCA = fs.readFileSync(argv['master-ca'], "utf8");
var mutualTlsCa;
try { // it's optional...
  mutualTlsCa = fs.readFileSync(argv['mutual-tls-ca'], "utf8");
} catch(err) {
  if (argv['auth-mode'] === 'mutual_tls') {
    throw "No CA read for mutual TLS. Looked in: " + argv['mutual-tls-ca'];
  } // otherwise, we don't need it
};
var proxyTLS = {};
try { // also optional TLS overrides (ciphersuite etc)
  proxyTLS = fs.readFileSync(argv['proxy-tlsopts-file'], "utf8");
  if (argv.debug) console.log("Read TLS opts from %s: %s", argv['proxy-tlsopts-file'], proxyTLS);
  proxyTLS = eval(proxyTLS);
  if (proxyTLS == null || ! typeof proxyTLS === 'object') {
    throw("TLS opts file did not evaluate to an object");
  }
} catch(e) {
  console.error("Could not read TLS opts from %s; error was: %s", argv['proxy-tlsopts-file'], e);
  proxyTLS = {};
} finally {
  proxyTLS['key'] = fs.readFileSync(argv['proxy-key'], "utf8");
  proxyTLS['cert'] = fs.readFileSync(argv['proxy-cert'], "utf8");
  if (argv.debug) {
    console.log("in finally, proxyTLS is:");
    console.log(proxyTLS);
  }
};
if(argv['debug']) {
  console.log("config values passed in:");
  var arg;
  for (arg in argv) {
    console.log("%s", arg + ": " + argv[arg]);
  }
  ["sessionSecret", "clientSecret", "masterCA", "mutualTlsCa", "proxyTLS"].forEach( function(val) {
    console.log("%s: ", val, eval(val));
  })
}

var cas = https.globalAgent.options.ca || [];
cas.push(masterCA);
https.globalAgent.options.ca = cas;

var openshiftUserUrl = urljoin(argv['master-url'], '/oapi/v1/users/~');

var validateBearerToken = function(accessToken, refreshToken, profile, done) {
  if (argv.debug) console.log("in validateBearerToken: ", accessToken, refreshToken, profile);
  if (!accessToken) {
    if (argv.debug) console.log("no access token, done.");
    done();
  }
  var authOptions = {
    url: openshiftUserUrl,
    headers: {
      authorization: 'Bearer ' + accessToken
    }
  };
  var authReq = request.get(authOptions);
  authReq.on('response', function(authRes) {
    if (authRes.statusCode != 200) {
      done();
    } else {
      var data = '';
      authRes.on('data', function (chunk){
        data += chunk;
      });
      authRes.on('end',function(){
        var user = JSON.parse(data);
        done(null, user);
      });
    }
  });
};

switch(argv['auth-mode']) {
  case 'oauth2':
    passport.use(new OAuth2Strategy({
        authorizationURL: urljoin(argv['public-master-url'], '/oauth/authorize'),
        tokenURL: urljoin(argv['master-url'], '/oauth/token'),
        clientID: argv['client-id'],
        clientSecret: clientSecret,
        callbackURL: argv['callback-url']
      },
      validateBearerToken
    ));
  case 'bearer':
    passport.use(new BearerStrategy(
      function(token, done) {
        validateBearerToken(token, null, null, done);
      }
    ));
};


passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

var proxy = new httpProxy.createProxyServer({
  target: argv.backend,
  changeOrigin: argv['use-backend-host-header']
});

proxy.on('error', function(e) {
  console.error("proxy error: %s", JSON.stringify(e));
});

var app = express();

app.use(morgan('combined'))

var useSession = argv['auth-mode'] === 'oauth2';

if (useSession) {
  app.use(sessions({
    cookieName: 'openshift-auth-proxy-session',
    requestKey: 'session',
    secret: sessionSecret, // should be a large unguessable string
    duration: parseDuration('' + argv['session-duration']), // how long the session will stay valid in ms
    activeDuration: parseDuration('' + argv['session-active-duration']), // if expiresIn < activeDuration, the session will be extended by activeDuration milliseconds,
    cookie: {
      ephemeral: argv['session-ephemeral']
    }
  }));

  app.use(passport.initialize());

  app.use(passport.session());

  app.get(argv['callback-url'], function(req, res) {
    var returnTo = req.session.returnTo;
    passport.authenticate(argv['auth-mode'])(req, res, function() {
      res.redirect(returnTo || '/');
    });
  });
} else {
  app.use(passport.initialize());
}

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    if (argv.debug) { console.log("authenticated, moving on.")}
    return next();
  }
  if (argv.debug) { console.log("not authenticated.")}
  if (useSession) {
    req.session.returnTo = req.path;
  }
  passport.authenticate(argv['auth-mode'], {session: useSession})(req, res, next);
}

proxy.on('proxyReq', function(proxyReq, req, res, options) {
  proxyReq.setHeader(argv['user-header'], req.user.metadata.name);
});

app.all('*', ensureAuthenticated, function(req, res) {
  proxy.web(req, res);
});

https.createServer(proxyTLS, app).listen(argv['listen-port']);

