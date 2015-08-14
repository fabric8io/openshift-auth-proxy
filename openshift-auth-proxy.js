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
      describe: 'Backend to proxy requests to',
      demand: true,
      default: process.env.OAP_BACKEND_URL
    }, 'use-backend-host-header': {
      describe: 'Change the host header to the backend URL',
      demand: true,
      type: 'boolean',
      default: false
    }, 'backend-ca': {
      describe: 'CA file used to validate backend server if secured'
    }, 'listen-port': {
      describe: 'Port to listen on',
      demand: true,
      default: Number(process.env.OAP_PROXY_PORT || 3000)
    }, 'auth-mode': {
      describe: 'Proxy auth mode',
      choices:  ['oauth2', 'bearer', 'mutual_tls', 'dummy'],
      default: process.env.OAP_AUTH_MODE || 'oauth2'
    }, 'plugin': {
      describe: 'Plugin for transforming the request/response after authentication',
      choices:  ['user_header', 'kibana_es', 'es', 'none'],
      default: process.env.OAP_PLUGIN || 'user_header'
    }, 'user-header': {
      describe: 'Header for sending user name on the proxied request',
      demand: true,
      default: process.env.OAP_REMOTE_USER_HEADER || 'X-Proxy-Remote-User'
    }, 'session-secret': {
      describe: 'File containing secret for encrypted session cookies',
      demand: true,
      default: process.env.OAP_SESSION_SECRET_FILE || 'secret/session-secret'
    }, 'session-duration': {
      describe: 'Duration for encrypted session cookies',
      demand: true,
      default: parseDuration(process.env.OAP_SESSION_DURATION || '1h')
    }, 'session-active-duration': {
      describe: 'Active duration for encrypted session cookies',
      demand: true,
      default: parseDuration('5m'),
      default: parseDuration(process.env.OAP_SESSION_ACTIVE_DURATION || '5m')
    }, 'session-ephemeral': {
      type: 'boolean',
      describe: 'Delete cookies on browser close',
      demand: true,
      default: true
    }, 'callback-url': {
      describe: 'oAuth callback URL',
      demand: true,
      default: process.env.OAP_CALLBACK_URL || '/auth/openshift/callback'
    }, 'client-id': {
      describe: 'OAuth client ID',
      demand: true,
      default: process.env.OAP_CLIENT_ID
    }, 'client-secret': {
      describe: 'OAuth client secret',
      demand: true,
      default: process.env.OAP_CLIENT_SECRET_FILE || 'secret/client-secret'
    }, 'master-url': {
      describe: 'Internal master address proxy will authenticate against',
      demand: true,
      default: process.env.OAP_MASTER_URL || 'https://kubernetes.default.svc.cluster.local:8443'
    }, 'public-master-url': {
      describe: 'Public master address for redirecting clients to',
      demand: true,
      default: process.env.OAP_PUBLIC_MASTER_URL
    }, 'master-ca': {
      describe: 'CA certificate[s] to validate connection to the master',
      demand: true,
      default: process.env.OAP_MASTER_CA_FILE || 'secret/master-ca'
    }, 'proxy-cert': {
      describe: 'Certificate file to use to listen for TLS',
      demand: true,
      default: process.env.OAP_PROXY_CERT_FILE || 'secret/proxy-cert'
    }, 'proxy-key': {
      describe: 'Key file to use to listen for TLS',
      demand: true,
      default: process.env.OAP_PROXY_KEY_FILE || 'secret/proxy-key'
    }, 'proxy-tlsopts-file': {
      describe: 'File containing JSON for proxy TLS options',
      demand: true,
      default: process.env.OAP_PROXY_TLS_FILE || 'secret/proxy-tls.json'
    }, 'mutual-tls-ca': {
      describe: 'CA cert file to use for validating TLS client certs under "mutual_tls" auth method',
      demand: false,
      default: process.env.OAP_PROXY_CA_FILE || 'secret/proxy-ca'
    }
  })
  .help('help')
  .epilog('copyright 2015')
  .argv;

// ---------------------- config --------------------------

//
// read in all the files with secrets, keys, certs
//
var sessionSecret;
try {
  sessionSecret = fs.readFileSync(argv['session-secret'])
} catch(err) {
  console.error("error reading session secret: %s", JSON.stringify(e));
} finally { // just ignore if the file is not there
  if (sessionSecret == null ) {
    console.error("generating session secret (will not work with scaled service)");
    sessionSecret = require('base64url')(require('crypto').randomBytes(256)).substring(0, 256);
  }
}
var clientSecret = fs.readFileSync(argv['client-secret'])
var masterCA = fs.readFileSync(argv['master-ca'])
var mutualTlsCa;
try { // it's optional...
  mutualTlsCa = fs.readFileSync(argv['mutual-tls-ca'])
} catch(err) {
  console.log("No CA read for mutual TLS.");
}
var proxyTLS = {};
try { // also optional TLS overrides (ciphersuite etc)
  proxyTLS = fs.readFileSync(argv['proxy-tlsopts-file'])
} finally {
  proxyTLS['key'] = fs.readFileSync(argv['proxy-key']);
  proxyTLS['cert'] = fs.readFileSync(argv['proxy-cert']);
}

//
// ensure we validate connecions to master w/ master CA
//
var cas = https.globalAgent.options.ca || [];
cas.push(masterCA);
https.globalAgent.options.ca = cas;

// where to get OpenShift user information for current auth
var openshiftUserUrl = urljoin(argv['master-url'], '/oapi/v1/users/~');


//
// ---------------------- passport auth --------------------------
//

//
// set up for passport authentication if needed
//
function userSerialization(user, done) {
  done(null, user);
}
var validateBearerToken = function(accessToken, refreshToken, profile, done) {
  if (!accessToken) {
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

var setupOauth = function(app) {
  passport.use(new OAuth2Strategy({
      authorizationURL: urljoin(argv['openshift-public-master'], '/oauth/authorize'),
      tokenURL: urljoin(argv['openshift-master'], '/oauth/token'),
      clientID: argv['client-id'],
      clientSecret: argv['client-secret'],
      callbackURL: argv['callback-url']
    },
    validateBearerToken
  ));
  app.use(sessions({
    cookieName: 'openshift-auth-proxy-session',
    requestKey: 'session',
    secret: argv['session-secret'], // should be a large unguessable string
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
}

var useSession = false;
var ensureAuthenticated = function(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  if (useSession) {
    req.session.returnTo = req.path;
  }
  passport.authenticate(argv['auth-mode'], {session: useSession})(req, res, next);
}


//
// ---------------------- proxy and handler --------------------------
//

//
// Create the handler for proxy server requests
//
var app = express();
app.use(morgan('combined'))

//
// Implement the configured authentication method
//
switch(argv['auth-mode']) {
  case 'oauth2':
    useSession = true;
    setupOauth(app);
    // NO break
  case 'bearer':
    passport.use(new BearerStrategy(
      function(token, done) {
        validateBearerToken(token, null, null, done);
      }
    ));
    app.use(passport.initialize());
    passport.serializeUser(userSerialization);
    passport.deserializeUser(userSerialization);
    break;
  case 'mutual_tls':
    if (mutualTlsCa == null) {
      throw "must supply 'mutual-tls-ca' to validate client connection";
    }
    proxyTLS['ca'] = mutualTlsCa;
    proxyTLS['requestCert'] = true;
    proxyTLS['rejectUnauthorized'] = true;
    ensureAuthenticated = function(req, res, next) {
      if (req.isAuthenticated()) { // TODO: applies here?
        return next();
      }
    };
    break;
  case 'dummy':
    req.user.metadata.name = 'dummy';
    ensureAuthenticated = function(req, res, next) {
        return next();
    };
    break;
};


//
// Set up the proxy server to delegate to our handler
//
var proxy = new httpProxy.createProxyServer({
  target: argv.backend,
  changeOrigin: argv['use-backend-host-header']
});
proxy.on('error', function(e) {
  console.error("proxy error: %s", JSON.stringify(e));
});
proxy.on('proxyReq', function(proxyReq, req, res, options) {
  proxyReq.setHeader(argv['user-header'], req.user.metadata.name);
});

app.all('*', ensureAuthenticated, function(req, res) {
  proxy.web(req, res);
});

https.createServer(proxyTLS, app).listen(argv['listen-port']);

