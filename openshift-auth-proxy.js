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
  .options({
    target: {
      describe: 'Target to proxy to',
      demand: true
    },
    'target-ca': {
      describe: 'CA used to valid target server'
    },
    'listen-port': {
      describe: 'Port to listen on',
      demand: true,
      default: 3000
    },
    'auth-mode': {
      describe: 'Auth mode',
      choices:  ['oauth2', 'bearer'],
      default: 'oauth2'
    },
    'user-header': {
      describe: 'Header to set the user name on the proxied request',
      demand: true,
      default: 'REMOTE_USER'
    },
    'session-secret': {
      describe: 'Secret for encrypted session cookies',
      demand: true,
      default: 'generated'
    },
    'session-duration': {
      describe: 'Duration for encrypted session cookies',
      demand: true,
      default: parseDuration('1h')
    },
    'session-active-duration': {
      describe: 'Active duration for encrypted session cookies',
      demand: true,
      default: parseDuration('5m')
    },
    'session-ephemeral': {
      type: 'boolean',
      describe: 'Delete cookies on browser close',
      demand: true,
      default: false
    },
    'callback-url': {
      describe: 'oAuth callback URL',
      demand: true,
      default: '/auth/openshift/callback'
    },
    'client-id': {
      describe: 'OAuth client ID',
      demand: true
    },
    'client-secret': {
      describe: 'OAuth client secret',
      demand: true
    },
    'openshift-master': {
      describe: 'OpenShift master to authenticate against',
      demand: true
    },
    'openshift-ca': {
      describe: 'CA certificate[s] to use',
      demand: true
    },
    'tls-cert': {
      describe: 'Certificate file to use to listen for TLS',
      demand: true
    },
    'tls-key': {
      describe: 'Key file to use to listen for TLS',
      demand: true
    }
  })
  .help('help')
  .epilog('copyright 2015')
  .argv;

if (argv['session-secret'] === 'generated') {
  require('base64url')(require('crypto').randomBytes(256)).substring(0, 256);
};

var cas = https.globalAgent.options.ca || [];
cas.push(fs.readFileSync(argv['openshift-ca']));
https.globalAgent.options.ca = cas;

var openshiftUserUrl = urljoin(argv['openshift-master'], '/oapi/v1/users/~');

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

switch(argv['auth-mode']) {
  case 'oauth2':
    passport.use(new OAuth2Strategy({
        authorizationURL: urljoin(argv['openshift-master'], '/oauth/authorize'),
        tokenURL: urljoin(argv['openshift-master'], '/oauth/token'),
        clientID: argv['client-id'],
        clientSecret: argv['client-secret'],
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
  target: argv.target
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
} else {
  app.use(passport.initialize());
}

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
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

https.createServer({
  key: fs.readFileSync(argv['tls-key']),
  cert: fs.readFileSync(argv['tls-cert'])
}, app).listen(argv['listen-port']);

