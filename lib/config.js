/*
 * Config
 *
 */

var parseDuration  = require('parse-duration'),
    fs             = require('fs');


function readSessionSecret(argv){
	var sessionSecret;
	try {
		sessionSecret = fs.readFileSync(argv['session-secret'], "utf8");
	} catch(err) {
		console.error("error reading session secret: %s", JSON.stringify(err));
	} finally { // just ignore if the file is not there
		if (sessionSecret == null ) {
			console.error("generating session secret (will not work with scaled service)");
			sessionSecret = require('base64url')(require('crypto').randomBytes(256)).substring(0, 256);
		}
	};
	return sessionSecret;
}

function readClientSecret(argv){
	return fs.readFileSync(argv['client-secret'], "utf8").replace(/(\n|\r)/gm,"");
}

function readMasterCA(argv){
	return fs.readFileSync(argv['master-ca'], "utf8");
}

function readMutualTlsCa(argv){
	var mutualTlsCa;
	try { // it's optional...
		mutualTlsCa = fs.readFileSync(argv['mutual-tls-ca'], "utf8");
	} catch(err) {
		if (argv['auth-mode'] === 'mutual_tls') {
			throw "No CA read for mutual TLS. Looked in: " + argv['mutual-tls-ca'];
		} // otherwise, we don't need it
	};
	return mutualTlsCa;
}

function readProxyTLS(argv){
	var proxyTLS = {};
	try { // also optional TLS overrides (ciphersuite etc)
		proxyTLS = fs.readFileSync(argv['proxy-tlsopts-file'], "utf8");
		if (argv.debug) console.log("Read TLS opts from %s: %s", argv['proxy-tlsopts-file'], proxyTLS);
		proxyTLS = eval(proxyTLS);
		if (proxyTLS == null || ! typeof proxyTLS === 'object') {
			throw("TLS opts file did not evaluate to an object");
		}
	} catch(e) {
		console.error("Could not read TLS opts from %s; error was: %s", argv['proxy-tlsopts-file'], e);
		proxyTLS = {};
	} finally {
		proxyTLS['key'] = fs.readFileSync(argv['proxy-key'], "utf8");
		proxyTLS['cert'] = fs.readFileSync(argv['proxy-cert'], "utf8");
		if (argv.debug) {
			console.log("in finally, proxyTLS is:");
			console.log(proxyTLS);
		}
	};
	return proxyTLS;
}

exports.init = function(argv){
	exports.sessionSecret = readSessionSecret(argv);
	exports.clientSecret = readClientSecret(argv);
	exports.masterCA = readMasterCA(argv);
	exports.mutualTlsCa = readMutualTlsCa(argv);
	exports.proxyTLS = readProxyTLS(argv);
}
exports.logConfig = function(){
	["sessionSecret", "clientSecret", "masterCA", "mutualTlsCa", "proxyTLS"].forEach( function(val) {
		console.log("%s: ", val, eval("exports."+val));
	})
}


