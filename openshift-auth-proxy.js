#!/usr/bin/env node

var express        = require('express'),
    sessions       = require('client-sessions'),
    passport       = require('passport'),
    OAuth2Strategy = require('passport-oauth2'),
    httpProxy      = require('http-proxy'),
    https          = require('https'),
    urljoin        = require('url-join'),
    request        = require('request'),
    morgan         = require('morgan'),
    parseDuration  = require('parse-duration'),
    fs             = require('fs');

var argv = require('yargs')
  .usage('Usage: $0 [options]')
  .demand('target')
  .nargs('target', 1)
  .describe('target', 'Target to proxy to')
  .nargs('target-ca', 1)
  .describe('target-ca', 'CA used to valid target server')
  .demand('listen-port')
  .nargs('listen-port', 1)
  .describe('listen-port', 'Port to listen on')
  .demand('user-header')
  .nargs('user-header', 1)
  .describe('user-header', 'Header to set the user name on the proxied request')
  .demand('session-secret')
  .nargs('session-secret', 1)
  .describe('session-secret', 'Secret for encrypted session cookies')
  .demand('session-duration')
  .nargs('session-duration', 1)
  .describe('session-duration', 'Duration for encrypted session cookies')
  .demand('session-active-duration')
  .nargs('session-active-duration', 1)
  .describe('session-active-duration', 'Active duration for encrypted session cookies')
  .demand('session-ephemeral')
  .nargs('session-ephemeral', 1)
  .describe('session-ephemeral', 'Duration for encrypted session cookies - set to -1 to delete when browser closes')
  .demand('callback-url')
  .nargs('callback-url', 1)
  .describe('callback-url', 'oAuth callback URL')
  .demand('client-id')
  .nargs('client-id', 1)
  .describe('client-id', 'OAuth client ID')
  .demand('client-secret')
  .nargs('client-secret', 1)
  .describe('client-secret', 'OAuth client secret')
  .demand('openshift-master')
  .describe('openshift-master', 'OpenShift master to authenticate against')
  .demand('openshift-ca')
  .nargs('openshift-ca', 1)
  .describe('openshift-ca', 'CA certificate[s] to use')
  .demand('tls-cert')
  .nargs('tls-cert', 1)
  .describe('tls-cert', 'Certificate file to use to listen for TLS')
  .demand('tls-key')
  .nargs('tls-key', 1)
  .describe('tls-key', 'Key file to use to listen for TLS')
  .implies('tls-cert', 'tls-key')
  .implies('tls-key', 'tls-cert')
  .help('h')
  .alias('h', 'help')
  .epilog('copyright 2015')
  .defaults({
    'listen-port': 3000,
    'callback-url': '/auth/openshift/callback',
    'session-secret': 'generated',
    'session-duration': parseDuration('1h'),
    'session-active-duration': parseDuration('5m'),
    'session-ephemeral': false,
    'user-header': 'REMOTE_USER'
  })
  .argv;

if (argv['session-secret'] === 'generated') {
  require('base64url')(require('crypto').randomBytes(256)).substring(0, 256);
};

var cas = https.globalAgent.options.ca || [];
cas.push(fs.readFileSync(argv['openshift-ca']));
https.globalAgent.options.ca = cas;

var openshiftUserUrl = urljoin(argv['openshift-master'], '/oapi/v1/users/~');

passport.use(new OAuth2Strategy({
    authorizationURL: urljoin(argv['openshift-master'], '/oauth/authorize'),
    tokenURL: urljoin(argv['openshift-master'], '/oauth/token'),
    clientID: argv['client-id'],
    clientSecret: argv['client-secret'],
    callbackURL: argv['callback-url']
  },
  function(accessToken, refreshToken, profile, done) {
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
  }
));

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

var proxy = new httpProxy.createProxyServer({
  target: argv.target
});

proxy.on('error', function(e) {
  console.error("proxy error: %s", JSON.stringify(e));
});

var app = express();

app.use(morgan('combined'))

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
  passport.authenticate('oauth2')(req, res, function() {
    res.redirect(returnTo || '/');
  });
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  req.session.returnTo = req.path;
  passport.authenticate('oauth2')(req, res, next);
}

proxy.on('proxyReq', function(proxyReq, req, res, options) {
  proxyReq.setHeader(argv['user-header'], req.user.metadata.name);
});

app.all('*', ensureAuthenticated, function(req, res) {
  proxy.web(req, res);
});

https.createServer({
  key: fs.readFileSync(argv['tls-key']),
  cert: fs.readFileSync(argv['tls-cert'])
}, app).listen(argv['listen-port']);

