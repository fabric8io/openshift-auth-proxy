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

var argv = require('./lib/options');
var config = require('./lib/config');
config.init(argv);

if(argv.debug){
	console.log("config values passed in:");
	argv.logArgs();
	config.logConfig();
}

var cas = https.globalAgent.options.ca || [];
cas.push(config.masterCA);
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
        clientSecret: config.clientSecret,
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
    secret: config.sessionSecret, // should be a large unguessable string
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

https.createServer(config.proxyTLS, app).listen(argv['listen-port']);

