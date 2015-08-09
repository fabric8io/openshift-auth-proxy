#!/usr/bin/env node

var http         = require('http'),
    https        = require('https'),
    request      = require('request'),
    fs           = require('fs'),
    httpProxy    = require('http-proxy'),
    finalhandler = require('finalhandler'),
    urljoin      = require('url-join'),
    morgan       = require('morgan');

var argv = require('yargs')
  .usage('Usage: $0 [options]')
  .example('$0 --target http://localhost:12345 --openshift-master https://localhost:8443 --openshift-ca /var/lib/openshift/openshift.local.config/master/ca.crt', 'proxy requests to http://localhost:12345, authenticating against openshift at https://localhost:8443 with CA certificate /var/lib/openshift/openshift.local.config/master/ca/crt')
  .demand('port')
  .nargs('port', 1)
  .describe('port', 'Port to listen on')
  .demand('target')
  .nargs('target', 1)
  .describe('target', 'Target to proxy to')
  .nargs('target-ca', 1)
  .describe('target-ca', 'CA used to valid target server')
  .demand('openshift-master')
  .describe('openshift-master', 'OpenShift master to authenticate against')
  .demand('openshift-ca')
  .nargs('openshift-ca', 1)
  .describe('openshift-ca', 'CA certificate[s] to use')
  .nargs('server-certificate', 1)
  .describe('server-certificate', 'Certificate file to use to listen for TLS')
  .nargs('server-key', 1)
  .describe('server-key', 'Key file to use to listen for TLS')
  .implies('server-certificate', 'server-key')
  .implies('server-key', 'server-certificate')
  .help('h')
  .alias('h', 'help')
  .epilog('copyright 2015')
  .defaults({
    port: 8080
  })
  .argv;

var proxy = new httpProxy.createProxyServer({
  target: argv.target
});

if (argv['target-ca']) {
  proxy.agent = new https.Agent({
    ca: fs.readFileSync(argv['target-ca'])
  });
}

proxy.on('proxyReq', function(proxyReq, req, res, options) {
  proxyReq.setHeader('X-WEBAUTH-USER', options.user.metadata.name);
});

proxy.on('error', function(e) {
  console.error("proxy error: %s", JSON.stringify(e));
});

var logger = morgan('combined');

var openshiftCACert = fs.readFileSync(argv['openshift-ca']);
var openshiftUserUrl = urljoin(argv['openshift-master'], '/oapi/v1/users/~');

var serverCallbackFunction = function (req, res) {
  var done = finalhandler(req, res);
  logger(req, res, function(err) {
    if (err) return done(err);

    var authOptions = {
      url: openshiftUserUrl,
      ca: openshiftCACert,
      headers: req.headers
    };
    var authReq = request.get(authOptions);
    authReq.on('response', function(authRes) {
      if (authRes.statusCode != 200) {
       authReq.pipe(res);
      } else {
        var data = '';
        authRes.on('data', function (chunk){
          data += chunk;
        });
        authRes.on('end',function(){
          var obj = JSON.parse(data);
          proxy.web(req, res, {
            user: obj
          });
        });
      }
    });
  });
};

var server = http.createServer(serverCallbackFunction);

if (argv['server-certificate'] && argv['server-key']) {
  var serverOptions = {
    key: fs.readFileSync(argv['server-key']),
    cert: fs.readFileSync(argv['server-certificate'])
  };

  server = https.createServer(serverOptions, serverCallbackFunction);
}

server.listen(argv.port);
