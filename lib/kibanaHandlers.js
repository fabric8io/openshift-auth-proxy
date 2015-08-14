#!/usr/bin/env node

var 
    url            = require('url'),
    bodyParser     = require('body-parser'),
    config         = require('./config');

var index = config['kibana-index'];
var indexUrlsPrefixes = [ '/' + index, '/_cluster/health/' + index];
var bodyRewritePrefixes = [ '/' + index, '/_mget' ];

function userIndex(user) { return index + '_' + user }
function userUriInsert(user) { return '_' + encodeURIComponent(user) }

//
// Implement the request transform(s)
//
function setupTransform(app, userForRequest) {
  var reqTransformer = function(req, res, next) {
    var reqUrl = url.parse(req.url);
    // rewrite kibana index urls to be user-specific
    indexUrlsPrefixes.forEach(function(prefix) {
      if (reqUrl.pathname.indexOf(prefix) === 0) {
        // need to rewrite to user-specific kibana index
  	reqUrl.pathname = prefix + userUriInsert(userForRequest(req)) +
                          reqUrl.pathname.substr(prefix.length);
        if (config.debug) console.log('rewriting path to "%s"', url.format(reqUrl));
        req.url = url.format(reqUrl);
      }
    });
    next();
  }

  var reqBodyRestreamer = function(req, res, next) {
    req.removeAllListeners('data')
    req.removeAllListeners('end')
    if(!req.body) { next(); return; }
    var newBody = JSON.stringify(req.body, null, "  ");
    if (config.debug) console.log('altered request body: ', newBody);
    // must adjust headers *before* passing on
    req.headers['content-length'] = newBody.length;
    next();
    // stream new body to later listener
    process.nextTick(function () {
      req.emit('data', newBody);
      req.emit('end');
    })
  }

  var reqBodyReindexer = function(req, res, next) {
    if (config.debug) console.log('request body: ', req.body);
    var user = userForRequest(req);
    try {
      req.body = JSON.parse(req.body, function(k,v) {
        if (k === '_index' && v === index)
          v += '_' + user;
        return v
      });
    } catch(e) { // json parsing can fail when humans write it
      console.error('Error parsing request body: ', e, '\nBody was:\n', req.body);
      req.body = {}
    }
    next();
  }

  var responseBodyReindexer = function(req, res, next) {
    // capture the original outgoing response write streams
    var resWrite = res.write.bind(res);
    var resEnd = res.end.bind(res);
    var resWriteHead = res.writeHead.bind(res);
    // replace original write streams, transforming the body
    var chunks = [];
    var newBody;
    res.write = function(chunk) { chunks.push(chunk) }
    res.writeHead = function(code, headers) {
      //res.removeHeader('Transfer-Encoding');
      //res.setHeader('Content-Length', newBody.length);
      res.removeHeader('Content-Length');
      resWriteHead(code, headers);
    }
    res.end = function() {
      var body = Buffer.concat(chunks);
      if (config.debug) console.log("response body: ", body.toString());
      var newIndex = userIndex(userForRequest(req));
      try {
        newBody = JSON.stringify(JSON.parse(body, function(k,v) {
          if (k === '_index' && v === newIndex)
            v = index;
	  else if (v !== null && typeof(v) === 'object' && newIndex in v){
            v[index] = v[newIndex];
	    delete v[newIndex];
	  }
          return v
        }));
      } catch(e) {
        console.error('Error parsing response body: ', e, '\nBody was:\n', body);
        newBody = body
      }
      if (config.debug) console.log("modified response body: ", newBody);
      resWrite(newBody);
      resEnd();
    }
    next();
  }
 
  if(config.transforms.indexOf('kibana_es') === null) return;
  // rewriting the body would be a potential performance hit; scope it only to where necessary.
  [ '/' + index, '/_mget' ].forEach(function(prefix) {
    // read in the body text, change kibana _index, and re-create the streaming body
    app.post(prefix, bodyParser.text({'type': '*/*'}), reqBodyReindexer, reqBodyRestreamer);
    // in the response body, revert kibana index
    app.use(prefix, responseBodyReindexer);
  });
  app.use(reqTransformer); // rewrite URL *after* previous bit has a chance to match it
}

module.exports = {
  setupTransform: setupTransform
}

