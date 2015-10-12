#!/usr/bin/env node

var express        = require('express'),
    https          = require('https'),
    morgan         = require('morgan'),
    config         = require('./lib/config'),
    authHandlers   = require('./lib/authHandlers'),
    proxy          = require('./lib/proxy');

// Define the express app that will handle server requests
var app = express();

// log requests in standard httpd "combined" format
app.use(morgan('combined'));

// Set up middleware to delegate to our handlers
authHandlers.setupAuthHandler(app);
proxy.setupProxy(app, authHandlers.userForRequest);

// Create the server feeding requests to our express app
console.log('Starting up the proxy with auth mode "%s" and proxy transform "%s".',
		config['auth-mode'], config.transforms.join() );
https.createServer(config.files.serverTLS, app).
      listen(config['listen-port']);

