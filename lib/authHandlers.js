var sessions       = require('client-sessions'),
    passport       = require('passport'),
    OAuth2Strategy = require('passport-oauth2'),
    BearerStrategy = require('passport-http-bearer'),
    urljoin        = require('url-join'),
    request        = require('request'),
    config         = require('./config'),
    parseDuration  = require('parse-duration');

//
// ---------------------- passport auth --------------------------
//

  var files = config.files;
  //
  // set up for passport authentication if it will be needed
  //
  var serializeUser = function(user, done) {
    done(null, user.metadata.name + '\n' + user.token);
  }
  var deserializeUser = function(userString, done) {
    var user = userString.split('\n');
    done(null, { 'token': user[1], 'metadata': { 'name': user[0] }});
  }

  var validateBearerToken = function(accessToken, refreshToken, profile, done) {
    if (config.debug) console.log('in validateBearerToken: ', accessToken, refreshToken, profile);
    if (!accessToken) {
      if (config.debug) console.log('no access token, done.');
      done();
    }
    var authOptions = {
      url: config.openshiftUserUrl,
      headers: {
        authorization: 'Bearer ' + accessToken
      }
    };
    var authReq = request.get(authOptions);
    authReq.on('response', function(authRes) {
      if(config.debug) console.log('in authReq');
      if (authRes.statusCode != 200) {
        done();
      } else {
        // collect response data, could be chunked
        var data = '';
        authRes.on('data', function (chunk){ data += chunk });
        authRes.on('end',function(){
          var user = JSON.parse(data);
          user.token = accessToken;
          done(null, user);
        });
      }
    });
  };

  var setupOauth = function(app) {
    passport.use(new OAuth2Strategy({
        authorizationURL: urljoin(config['public-master-url'], '/oauth/authorize'),
        tokenURL: urljoin(config['master-url'], '/oauth/token'),
        clientID: config['oauth-id'],
        clientSecret: files.oauthSecret,
        callbackURL: config['callback-url']
      },
      validateBearerToken
    ));
    app.use(sessions({
      cookieName: 'openshift-auth-proxy-session',
      requestKey: 'session',
      secret: files.sessionSecret, // should be a large unguessable string
      duration: parseDuration('' + config['session-duration']), // how long the session will stay valid in ms
      activeDuration: parseDuration('' + config['session-active-duration']), // if expiresIn < activeDuration, the session will be extended by activeDuration milliseconds,
      cookie: {
        ephemeral: config['session-ephemeral']
      }
    }));
    app.use(passport.initialize());
    app.use(passport.session());
    app.get(config['callback-url'], function(req, res) {
      if (config.debug) console.log('in callback handler for req path %s', req.path);
      var returnTo = req.session.returnTo;
      passport.authenticate(config['auth-mode'])(req, res, function() {
        res.redirect(returnTo || '/');
      });
    });
  }

  var setupBearer = function(app) {
    var bearer = new BearerStrategy( function(token, done) { validateBearerToken(token, null, null, done) });
    var oldAuth = bearer.__proto__.authenticate; // need to wrap existing function to extract token from query
    bearer.authenticate = function(req) {
      if (req.query && req.query['openshift_auth_token']) {
        if (config.debug) console.log("req query has auth token.");
        req.headers.authorization = 'Bearer ' + req.query['openshift_auth_token'];
        delete req.query['openshift_auth_token'];
      }
      oldAuth.call(this, req);
    }
    passport.use(bearer);
    app.use(passport.initialize());
    passport.serializeUser(serializeUser);
    passport.deserializeUser(deserializeUser);
  }

  var useSession = false;
  var ensureAuthenticated = function(req, res, next) {
    if (config.debug) console.log('in passport.ensureAuthenticated for req path ' + req.path);
    if (req.isAuthenticated()) {
      if (config.debug) { console.log('authenticated, moving on.')}
      return next();
    }
    if (config.debug) { console.log('not authenticated.')}
    if (useSession) {
      req.session.returnTo = req.path;
    }
    switch(config['auth-mode']) {
      case 'oauth2':
        //passport.authenticate(['bearer', 'oauth2'], {session: useSession})(req, res, next);
        passport.authenticate('oauth2', {session: useSession})(req, res, next);
	break;
      case 'bearer':
        passport.authenticate('bearer', {session: useSession})(req, res, next);
	break;
    }
  }

  //
  // Implement the configured authentication method handler
  //
  var setupAuthHandler = function(app) {
    switch(config['auth-mode']) {
      case 'oauth2':
        useSession = true;
        setupBearer(app);
        setupOauth(app);
	break;
      case 'bearer':
        setupBearer(app);
        break;
      case 'mutual_tls':
        if (!files.mutualTlsCa) {
          throw 'must supply "mutual-tls-ca" to validate client connection';
        }
        files.serverTLS['ca'] = files.mutualTlsCa;
        files.serverTLS['requestCert'] = true;
        files.serverTLS['rejectUnauthorized'] = true;
        ensureAuthenticated = function(req, res, next) {
          if (config.debug) console.log('in mutual_tls.ensureAuthenticated for req path ' + req.path);
          if (config.debug) console.log('client cert is: ', req.connection.getPeerCertificate());
          var userName = req.connection.getPeerCertificate().subject['CN'];
          req.user = { metadata: { name: userName }};
          return next();
        };
        break;
      case 'dummy':
        ensureAuthenticated = function(req, res, next) {
          if (config.debug) console.log('in dummy.ensureAuthenticated for req path ' + req.path);
          req.user = { metadata: { name: 'dummy'}};
          return next();
        };
        break;
      case 'none':
        ensureAuthenticated = function(req, res, next) { return next() }
        break;
    };
    app.use(ensureAuthenticated);
  }

  var userForRequest = function (req) {
    var user = { 'name': req.user.metadata.name};
    if (req.user.token) user.token = req.user.token
    if (config.debug) console.log('request user is: ', user);
    if (config['trust-remote-user']) {
      // Trust/forward the remote user header if given.
      var headerName = req.headers[config['user-header'].toLowerCase()];
      if (config.debug) console.log('header user is "%s"', headerName);
      if (headerName) user.name = headerName;
    }
    return user;
  }

module.exports = {
    setupAuthHandler: setupAuthHandler,
    userForRequest:   userForRequest
  }
