var sessions       = require('client-sessions'),
    passport       = require('passport'),
    OAuth2Strategy = require('passport-oauth2'),
    BearerStrategy = require('passport-http-bearer'),
    urljoin        = require('url-join'),
    request        = require('request'),
    bodyParser     = require('body-parser'),
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
    done(null, {
	         'token': user[1],
		 'metadata': {
		      'name': user[0]
		 }
               });
  }

  //
  // callback to check that a token is valid and pass on the user data
  //
  var validateBearerToken = function(accessToken, refreshToken, profile, done) {
    config.debugLog('in validateBearerToken');
    if (!accessToken) {
      config.debugLog('no access token, done.');
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
      config.debugLog('in authReq');
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
    // configure passport into the request w / oauth
    passport.use(new OAuth2Strategy({
        authorizationURL: urljoin(config['public-master-url'], '/oauth/authorize'),
        tokenURL: urljoin(config['master-url'], '/oauth/token'),
        clientID: config['oauth-id'],
        clientSecret: files.oauthSecret,
        callbackURL: config['callback-url']
      },
      validateBearerToken
    ));
    // we will record the user name + token in the session
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
      config.debugLog('in callback handler for req path %s', req.path);
      var returnTo = req.session.returnTo;
      passport.authenticate(config['auth-mode'])(req, res, function() {
        res.redirect(returnTo || '/');
      });
    });
  }

  var setupBearer = function(path, app) {
    if (app == null) { app = path; path = null }
    var bearer = new BearerStrategy(
		    function(token, done) {
		      validateBearerToken(token, null, null, done)
		    }
		 );
    config.debugLog('in setupBearer');
    passport.use(bearer);
    if (path) app.use(path, passport.initialize());
    else      app.use(passport.initialize());
    passport.serializeUser(serializeUser);
    passport.deserializeUser(deserializeUser);
  }

  var setupTokenRedirect = function(path, app) {
    app.use(path, function(req, res, next) {
      var target;
      if (req.query) target = req.query.redirect;
      if (req.body)  target = req.body.redirect || target;
      if (target != null && target.indexOf("/") === 0)
        res.redirect(target);
      else
        res.status(400).end('require "redirect" parameter beginning with "/"');
    });
  }

  var handleLogout = function(req, res, next) {
    req.logout();
    res.redirect(config.logoutRedirect || "/");
  };

  var useSession = false;
  var ensureAuthenticated = function(req, res, next) {
    config.debugLog('in passport.ensureAuthenticated for req path ' + req.path);
    if (req.isAuthenticated()) {
      config.debugLog('authenticated by request session.');
      return next();
    }
    config.debugLog('not authenticated by request session.');
    if (useSession) {
      req.session.returnTo = req.path;
    }
    switch(config['auth-mode']) {
      case 'oauth2':
        passport.authenticate(['bearer', 'oauth2'], {session: useSession})(req, res, next);
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
	app.use("/auth/logout", handleLogout);
        app.use("/auth/token", bodyParser.urlencoded({ extended: true })); // required to auth with POST params
        app.use(ensureAuthenticated);
        setupTokenRedirect("/auth/token", app);
	break;
      case 'bearer':
        setupBearer(app);
        app.use(ensureAuthenticated);
        break;
      case 'mutual_tls':
        if (!files.mutualTlsCa) {
          throw 'must supply "mutual-tls-ca" to validate client connection';
        }
        files.serverTLS['ca'] = files.mutualTlsCa;
        files.serverTLS['requestCert'] = true;
        files.serverTLS['rejectUnauthorized'] = true;
        app.use(function(req, res, next) {
          config.debugLog('in mutual_tls.ensureAuthenticated for req path ' + req.path);
          config.debugLog('client cert is: ', req.connection.getPeerCertificate());
          var userName = req.connection.getPeerCertificate().subject['CN'];
          req.user = { metadata: { name: userName }};
          return next();
        });
        break;
      case 'dummy':
        app.use(function(req, res, next) {
          config.debugLog('in dummy.ensureAuthenticated for req path ' + req.path);
          req.user = { metadata: { name: 'dummy'}};
          return next();
        });
        break;
      case 'none':
        app.use(function(req, res, next) { return next() });
        break;
    };
  }

  var userForRequest = function (req) {
    var user = { 'name': req.user.metadata.name};
    if (req.user.token) user.token = req.user.token
    config.debugLog('request user is: ', user.name);
    if (config['trust-remote-user']) {
      // Trust/forward the remote user header if given.
      var headerName = req.headers[config['user-header'].toLowerCase()];
      config.debugLog('header user is "%s"', headerName);
      if (headerName) user.name = headerName;
    }
    return user;
  }

module.exports = {
    setupAuthHandler: setupAuthHandler,
    userForRequest:   userForRequest
  }
