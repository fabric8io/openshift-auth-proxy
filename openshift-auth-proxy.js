#!/usr/bin/env node

var https     = require('https'),
    request   = require('request'),
    fs        = require('fs'),
    httpProxy = require('http-proxy');

var proxy = new httpProxy.createProxyServer({
  target: 'http://localhost:12345'
});

proxy.on('proxyReq', function(proxyReq, req, res, options) {
  proxyReq.setHeader('X-WEBAUTH-USER', options.user.metadata.name);
});

var serverOptions = {
  key: fs.readFileSync('/var/lib/openshift/openshift.local.config/master/master.server.key', 'utf8'),
  cert: fs.readFileSync('/var/lib/openshift/openshift.local.config/master/master.server.crt', 'utf8')
};

https.createServer(serverOptions, function (req, res) {
  var authOptions = {
    url: 'https://localhost:8443/oapi/v1/users/~/',
    ca: fs.readFileSync('/var/lib/openshift/openshift.local.config/master/ca.crt', 'utf8'),
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
}).listen(8080);
