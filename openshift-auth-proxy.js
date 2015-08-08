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
  .example('$0 -t http://localhost:12345 -o https://localhost:8443 -c /var/lib/openshift/openshift.local.config/master/ca.crt', 'proxy requests to http://localhost:12345, authenticating against openshift at https://localhost:8443 with CA certificate /var/lib/openshift/openshift.local.config/master/ca/crt')
  .demand('t')
  .alias('t', 'target')
  .nargs('t', 1)
  .describe('t', 'Target to proxy to')
  .demand('o')
  .alias('o', 'openshift')
  .nargs('o', 1)
  .describe('o', 'OpenShift server to authenticate against')
  .demand('c')
  .alias('c', 'ca')
  .nargs('c', 1)
  .describe('c', 'CA certificate[s] to use')
  .help('h')
  .alias('h', 'help')
  .epilog('copyright 2015')
  .argv;

var proxy = new httpProxy.createProxyServer({
  target: argv.target//localhost:12345'//,
//  agent: new https.Agent({
//    ca: fs.readFileSync('/var/lib/openshift/openshift.local.config/master/ca.crt', 'utf8')
//  })
});

proxy.on('proxyReq', function(proxyReq, req, res, options) {
  proxyReq.setHeader('X-WEBAUTH-USER', options.user.metadata.name);
});

proxy.on('error', function(e) {
  console.log(e);
});

var serverOptions = {
  key: fs.readFileSync('/var/lib/openshift/openshift.local.config/master/master.server.key', 'utf8'),
  cert: fs.readFileSync('/var/lib/openshift/openshift.local.config/master/master.server.crt', 'utf8')
};

var logger = morgan('combined');

http.createServer(function (req, res) {
  var done = finalhandler(req, res);
  logger(req, res, function(err) {
    if (err) return done(err);

    var authOptions = {
      url: urljoin(argv.openshift, '/oapi/v1/users/~'),
      ca: fs.readFileSync(argv.ca, 'utf8'),
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
}).listen(8080);
